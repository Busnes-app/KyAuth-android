package org.kysecurity.authenticator.passkeys

import android.content.Intent
import android.credentials.ClearCredentialStateException
import android.credentials.CreateCredentialException
import android.credentials.GetCredentialException
import android.os.Build
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.service.credentials.BeginCreateCredentialRequest
import android.service.credentials.BeginCreateCredentialResponse
import android.service.credentials.BeginGetCredentialRequest
import android.service.credentials.BeginGetCredentialResponse
import android.service.credentials.ClearCredentialStateRequest
import android.service.credentials.CredentialProviderService
import androidx.annotation.RequiresApi
import org.json.JSONObject
import org.kysecurity.authenticator.pairing.PairingStore

/**
 * System Credential Provider for the KyIdentity login passkey only. It holds no vault and offers
 * no unlock action: the passkey's key is hardware-resident and needs no vault key.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class KyAuthCredentialProviderService : CredentialProviderService() {

    override fun onBeginGetCredential(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        // Verifying a native caller against the relying party fetches over the network, so this
        // must not run on the binder thread.
        Thread { callback.onResult(buildGetResponse(request)) }.start()
    }

    private fun buildGetResponse(request: BeginGetCredentialRequest): BeginGetCredentialResponse {
        val identityPasskey = IdentityPasskeyStore(this).record()
            ?: return BeginGetCredentialResponse.Builder().build()
        return CredentialEntryBuilder.build(this, request, identityPasskey)
    }

    override fun onBeginCreateCredential(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        Thread { callback.onResult(buildCreateResponse(request)) }.start()
    }

    private fun buildCreateResponse(request: BeginCreateCredentialRequest): BeginCreateCredentialResponse {
        val callingAppInfo = request.callingAppInfo
        val origin = callingAppInfo?.origin
        val webOriginHost = ClientData.webOriginHost(origin)
        val callerPackage = callingAppInfo?.packageName
        val callerOrigin = origin ?: ClientData.apkKeyHashOrigin(callingAppInfo?.signingInfo)
        val responseBuilder = BeginCreateCredentialResponse.Builder()

        if (
            request.type == CredentialEntryBuilder.TYPE_PUBLIC_KEY ||
            request.type == CredentialEntryBuilder.TYPE_PUBLIC_KEY_ANDX
        ) {
            val requestJson = request.data.getString(CredentialEntryBuilder.BUNDLE_KEY_REQUEST_JSON)
                ?: request.data.getString(CredentialEntryBuilder.BUNDLE_KEY_REQUEST_JSON_LEGACY).orEmpty()
            val json = runCatching { JSONObject(requestJson) }.getOrNull() ?: run {
                return responseBuilder.build()
            }
            val rpId = RpId.validate(json.optJSONObject("rp")?.optString("id"), webOriginHost) ?: run {
                // Refuse to mint a credential for an RP ID the caller has no claim to.
                return responseBuilder.build()
            }
            // A failed pairing read cannot rule out KyIdentity, so it refuses.
            val pairing = runCatching { PairingStore(this).account()?.serverUrl }
            if (pairing.isFailure) return responseBuilder.build()
            // Only the exact paired KyIdentity host, and before any network work.
            if (!identityCreateTarget(rpId, pairing.getOrNull())) return responseBuilder.build()
            if (webOriginHost == null &&
                !DigitalAssetLinks.isCallerAuthorized(rpId, callerPackage, callingAppInfo?.signingInfo)
            ) {
                return responseBuilder.build()
            }
            val userObj = json.optJSONObject("user")
            val username = userObj?.optString("name")?.ifBlank { null }
                ?: userObj?.optString("displayName").orEmpty()
            val title = "Create KyIdentity Passkey"
            val subtitle = "Stays on this device, in secure hardware"

            val intent = Intent(this, CredentialAuthActivity::class.java).apply {
                putExtra(CredentialAuthActivity.EXTRA_ACTION, CredentialAuthActivity.ACTION_CREATE_IDENTITY_PASSKEY)
                putExtra(CredentialAuthActivity.EXTRA_REQUEST_JSON, requestJson)
                putExtra(CredentialAuthActivity.EXTRA_RP_ID, rpId)
                putExtra(CredentialAuthActivity.EXTRA_ORIGIN, callerOrigin)
                putExtra(CredentialAuthActivity.EXTRA_CALLER_PACKAGE, callerPackage)
                putExtra(
                    CredentialAuthActivity.EXTRA_CLIENT_DATA_HASH,
                    // Only a privileged browser may dictate the signed client data.
                    ClientData.privilegedClientDataHash(
                        origin,
                        request.data.getByteArray(CredentialEntryBuilder.BUNDLE_KEY_CLIENT_DATA_HASH),
                    ),
                )
                putExtra(CredentialAuthActivity.EXTRA_USERNAME, username)
                putExtra(CredentialAuthActivity.EXTRA_DISPLAY_TITLE, title)
                putExtra(CredentialAuthActivity.EXTRA_DISPLAY_SUBTITLE, subtitle)
            }

            responseBuilder.setCreateEntries(
                listOf(
                    CredentialSliceHelper.createCreateCredentialEntry(
                        context = this,
                        request = request,
                        title = title,
                        subtitle = subtitle,
                        createIntent = intent,
                        requestCode = 2001,
                    ),
                ),
            )
        }

        return responseBuilder.build()
    }

    override fun onClearCredentialState(
        request: ClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialStateException>,
    ) {
        callback.onResult(null)
    }
}
