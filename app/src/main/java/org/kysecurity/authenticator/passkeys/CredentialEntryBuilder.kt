package org.kysecurity.authenticator.passkeys

import android.content.Context
import android.content.Intent
import android.content.pm.SigningInfo
import android.os.Build
import android.service.credentials.BeginGetCredentialOption
import android.service.credentials.BeginGetCredentialRequest
import android.service.credentials.BeginGetCredentialResponse
import androidx.annotation.RequiresApi
import org.json.JSONObject

/**
 * The only RP ID this provider will mint a passkey for: exactly the paired KyIdentity host. Checked
 * before any network work, so an unrelated RP ID costs nothing and reveals nothing.
 */
internal fun identityCreateTarget(rpId: String, serverUrl: String?): Boolean =
    IdentityPasskey.isIdentityRpId(rpId, serverUrl)

/**
 * Turns a credential query into the entries offered to the user: at most the hardware-backed
 * KyIdentity passkey, which needs no vault key and is offered whether or not KyAuth is unlocked.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
object CredentialEntryBuilder {

    fun build(
        context: Context,
        request: BeginGetCredentialRequest,
        identityPasskey: IdentityPasskeyRecord?,
    ): BeginGetCredentialResponse {
        val callingAppInfo = request.callingAppInfo
        val origin = callingAppInfo?.origin
        val webOriginHost = ClientData.webOriginHost(origin)
        val callerPackage = callingAppInfo?.packageName
        val callerOrigin = origin ?: ClientData.apkKeyHashOrigin(callingAppInfo?.signingInfo)

        val responseBuilder = BeginGetCredentialResponse.Builder()
        var requestCode = 1000
        for (option in request.beginGetCredentialOptions) {
            if (option.type == TYPE_PUBLIC_KEY || option.type == TYPE_PUBLIC_KEY_ANDX) {
                addPasskeyEntries(
                    context, option, identityPasskey, webOriginHost, callerPackage, callerOrigin,
                    origin, callingAppInfo?.signingInfo, responseBuilder, requestCode++,
                )
            }
        }
        return responseBuilder.build()
    }

    private fun addPasskeyEntries(
        context: Context,
        option: BeginGetCredentialOption,
        identityPasskey: IdentityPasskeyRecord?,
        webOriginHost: String?,
        callerPackage: String?,
        callerOrigin: String?,
        callerWebOrigin: String?,
        callerSigningInfo: SigningInfo?,
        responseBuilder: BeginGetCredentialResponse.Builder,
        requestCode: Int,
    ) {
        val requestJson = option.candidateQueryData.getString(BUNDLE_KEY_REQUEST_JSON)
            ?: option.candidateQueryData.getString(BUNDLE_KEY_REQUEST_JSON_LEGACY).orEmpty()
        val json = runCatching { JSONObject(requestJson) }.getOrNull() ?: return

        // Fail closed: an RP ID we cannot validate against the caller gets no entries at all.
        val rpId = RpId.validate(json.optString("rpId"), webOriginHost) ?: return
        // Stop before the DigitalAssetLinks fetch below unless this is the enrolled KyIdentity
        // passkey: that fetch is an HTTPS request to a host the caller names, and it must not reveal
        // whether a KyIdentity passkey is enrolled.
        if (identityPasskey?.rpId != rpId) return
        // A native caller named this RP itself; only the RP can confirm the claim.
        if (webOriginHost == null &&
            !DigitalAssetLinks.isCallerAuthorized(rpId, callerPackage, callerSigningInfo)
        ) {
            return
        }
        // Only a privileged browser may dictate the signed client data; see ClientData.
        val clientDataHash = ClientData.privilegedClientDataHash(
            callerWebOrigin,
            option.candidateQueryData.getByteArray(BUNDLE_KEY_CLIENT_DATA_HASH),
        )

        // The hardware-backed KyIdentity passkey. Offered without any vault key, so it survives the
        // password vault being locked, compromised, or in recovery.
        if (identityPasskey != null && identityPasskey.rpId == rpId) {
            val title = identityPasskey.username.ifBlank { rpId }
            val intent = Intent(context, CredentialAuthActivity::class.java).apply {
                putExtra(CredentialAuthActivity.EXTRA_ACTION, CredentialAuthActivity.ACTION_GET_IDENTITY_PASSKEY)
                putExtra(CredentialAuthActivity.EXTRA_REQUEST_JSON, requestJson)
                putExtra(CredentialAuthActivity.EXTRA_RP_ID, rpId)
                putExtra(CredentialAuthActivity.EXTRA_ORIGIN, callerOrigin)
                putExtra(CredentialAuthActivity.EXTRA_CALLER_PACKAGE, callerPackage)
                putExtra(CredentialAuthActivity.EXTRA_CLIENT_DATA_HASH, clientDataHash)
                putExtra(CredentialAuthActivity.EXTRA_DISPLAY_TITLE, "Sign in to KyIdentity")
                putExtra(CredentialAuthActivity.EXTRA_DISPLAY_SUBTITLE, "$title (Passkey • this device)")
            }
            responseBuilder.addCredentialEntry(
                CredentialSliceHelper.createGetCredentialEntry(
                    context = context,
                    option = option,
                    title = title,
                    subtitle = "Passkey • this device",
                    fillIntent = intent,
                    requestCode = requestCode + 500,
                ),
            )
        }
    }

    const val TYPE_PUBLIC_KEY = "android.credentials.TYPE_PUBLIC_KEY_CREDENTIAL"
    const val TYPE_PUBLIC_KEY_ANDX = "androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL"

    const val BUNDLE_KEY_REQUEST_JSON = "androidx.credentials.BUNDLE_KEY_REQUEST_JSON"
    const val BUNDLE_KEY_REQUEST_JSON_LEGACY =
        "android.credentials.GetPublicKeyCredentialOption.BUNDLE_KEY_REQUEST_JSON"
    const val BUNDLE_KEY_CLIENT_DATA_HASH = "androidx.credentials.BUNDLE_KEY_CLIENT_DATA_HASH"
}
