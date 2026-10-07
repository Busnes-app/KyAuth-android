package org.kysecurity.authenticator.passkeys

import android.app.Activity
import android.content.Intent
import android.credentials.CreateCredentialException
import android.credentials.CreateCredentialResponse
import android.credentials.Credential
import android.credentials.GetCredentialException
import android.credentials.GetCredentialResponse
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import androidx.annotation.RequiresApi
import android.service.credentials.CredentialProviderService
import android.util.Base64
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import java.nio.charset.StandardCharsets
import java.security.Signature
import org.json.JSONObject
import org.kysecurity.authenticator.R
import org.kysecurity.authenticator.ThemeManager
import org.kysecurity.authenticator.pairing.PairingStore
import org.kysecurity.authenticator.security.VaultUnlockPrompt

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class CredentialAuthActivity : AppCompatActivity() {

    private lateinit var usernameInput: EditText

    /**
     * True from the moment an enrolment claims the spare alias until the Activity finishes.
     *
     * Two taps of Save before the BiometricPrompt takes focus would both see no stored record,
     * pick the same spare alias, and the second generate() would destroy the first key while its
     * prompt was still live — registering a public key on the server whose private half no longer
     * exists. Guarded with a flag rather than by disabling the button: the button is a local in
     * onCreate and not the only way in, and the resource being protected is the alias, not the tap.
     */
    private var enrolling = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val action = intent.getStringExtra(EXTRA_ACTION) ?: run {
            finishWithFailure("Invalid credential action")
            return
        }

        val promptTitle = intent.getStringExtra(EXTRA_DISPLAY_TITLE) ?: "KyAuth Verification"
        val promptSubtitle = intent.getStringExtra(EXTRA_DISPLAY_SUBTITLE) ?: ""
        val isCreation = action == ACTION_CREATE_IDENTITY_PASSKEY

        val rootLayout = FrameLayout(this).apply {
            layoutParams = ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
            setBackgroundColor(0x99000000.toInt())
        }

        val density = resources.displayMetrics.density
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = (24 * density).toInt()
            setPadding(pad, pad, pad, pad)
            background = GradientDrawable().apply {
                setColor(ThemeManager.color(this@CredentialAuthActivity, R.color.ky_surface))
                cornerRadius = 24 * density
                setStroke((1 * density).toInt(), ThemeManager.color(this@CredentialAuthActivity, R.color.ky_border))
            }
            layoutParams = FrameLayout.LayoutParams(
                (360 * density).toInt(),
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply {
                gravity = Gravity.CENTER
            }
        }

        val appLabel = TextView(this).apply {
            text = getString(R.string.app_name)
            setTextColor(ThemeManager.color(this@CredentialAuthActivity, R.color.ky_cyan))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER
        }
        card.addView(appLabel)

        val titleView = TextView(this).apply {
            text = promptTitle
            setTextColor(ThemeManager.color(this@CredentialAuthActivity, R.color.ky_text))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 18f)
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER
            setPadding(0, (8 * density).toInt(), 0, 0)
        }
        card.addView(titleView)

        val subtitleView = TextView(this).apply {
            text = promptSubtitle
            setTextColor(ThemeManager.color(this@CredentialAuthActivity, R.color.ky_muted))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
            gravity = Gravity.CENTER
            setPadding(0, (4 * density).toInt(), 0, (16 * density).toInt())
        }
        card.addView(subtitleView)

        if (action == ACTION_CREATE_IDENTITY_PASSKEY) {
            val initialUser = intent.getStringExtra(EXTRA_USERNAME).orEmpty()
            usernameInput = EditText(this).apply {
                hint = "Username or display name"
                setText(initialUser)
                styleInputField(this, density)
            }
            card.addView(usernameInput, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (48 * density).toInt()).apply {
                bottomMargin = (18 * density).toInt()
            })
        }

        val buttonContainer = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
        }

        val cancelButton = Button(this).apply {
            text = getString(R.string.cancel)
            setTextColor(ThemeManager.color(this@CredentialAuthActivity, R.color.ky_muted))
            background = GradientDrawable().apply {
                setColor(ThemeManager.color(this@CredentialAuthActivity, R.color.ky_surface_elevated))
                cornerRadius = 14 * density
            }
            setOnClickListener { finishWithCancellation() }
            layoutParams = LinearLayout.LayoutParams(0, (48 * density).toInt(), 1f).apply {
                marginEnd = (8 * density).toInt()
            }
        }
        buttonContainer.addView(cancelButton)

        val confirmButton = Button(this).apply {
            text = if (isCreation) "Save" else "Verify"
            setTextColor(ThemeManager.buttonText(this@CredentialAuthActivity))
            background = GradientDrawable().apply {
                setColor(ThemeManager.color(this@CredentialAuthActivity, R.color.ky_cyan))
                cornerRadius = 14 * density
            }
            setOnClickListener { authenticateAndExecute(action) }
            layoutParams = LinearLayout.LayoutParams(0, (48 * density).toInt(), 1f).apply {
                marginStart = (8 * density).toInt()
            }
        }
        buttonContainer.addView(confirmButton)
        card.addView(buttonContainer)

        val scrollView = ScrollView(this).apply {
            layoutParams = FrameLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                gravity = Gravity.CENTER
            }
            addView(card)
        }
        rootLayout.addView(scrollView)
        setContentView(rootLayout)

        // For retrieval, automatically prompt for fast 1-tap UX
        if (!isCreation) {
            authenticateAndExecute(action)
        }
    }

    private fun styleInputField(editText: EditText, density: Float) {
        editText.setTextColor(ThemeManager.color(this, R.color.ky_text))
        editText.setHintTextColor(ThemeManager.color(this, R.color.ky_muted))
        editText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
        val padH = (14 * density).toInt()
        val padV = (10 * density).toInt()
        editText.setPadding(padH, padV, padH, padV)
        editText.background = GradientDrawable().apply {
            setColor(ThemeManager.color(this@CredentialAuthActivity, R.color.ky_surface_elevated))
            cornerRadius = 12 * density
            setStroke((1 * density).toInt(), ThemeManager.color(this@CredentialAuthActivity, R.color.ky_border))
        }
    }

    private fun authenticateAndExecute(action: String) {
        when (action) {
            ACTION_GET_IDENTITY_PASSKEY -> getIdentityPasskey()
            ACTION_CREATE_IDENTITY_PASSKEY -> createIdentityPasskey()
            else -> finishWithFailure("Unknown credential action: $action")
        }
    }

    /**
     * Asserts with the hardware-backed KyIdentity passkey. The private key is
     * non-exportable and needs no vault key, so this works while KyAuth is locked.
     *
     * Known and deliberate: the request's `allowCredentials` is ignored.
     * There is at most one KyIdentity passkey per device, so the only effect is asserting with it
     * when the RP asked for a credential id this device does not hold, which the RP then rejects.
     */
    private fun getIdentityPasskey() {
        val store = IdentityPasskeyStore(applicationContext)
        val record = store.record() ?: return finishWithFailure("No KyIdentity passkey on this device")

        val requestJson = intent.getStringExtra(EXTRA_REQUEST_JSON).orEmpty()
        val json = runCatching { JSONObject(requestJson) }.getOrNull()
            ?: return finishWithFailure("Malformed passkey request")
        val rpId = intent.getStringExtra(EXTRA_RP_ID)?.takeIf { it.isNotBlank() }
            ?: return finishWithFailure("Request has no relying party")
        if (RpId.normalize(json.optString("rpId")) != rpId) {
            return finishWithFailure("Relying party does not match the request")
        }
        if (record.rpId != rpId) {
            return finishWithFailure("This passkey does not belong to $rpId")
        }
        val challenge = json.optString("challenge").takeIf { it.isNotBlank() }
            ?: return finishWithFailure("Request has no challenge")

        val callerHash = intent.privilegedClientDataHash()
        val clientDataJson = if (callerHash != null) {
            null
        } else {
            val origin = intent.getStringExtra(EXTRA_ORIGIN)?.takeIf { it.isNotBlank() }
                ?: return finishWithFailure("Caller origin is unavailable")
            ClientData.serialize(
                ClientData.TYPE_GET,
                challenge,
                origin,
                intent.getStringExtra(EXTRA_CALLER_PACKAGE),
            )
        }
        val clientDataHash = callerHash ?: WebAuthnEngine.sha256(requireNotNull(clientDataJson))

        val signature = IdentityPasskeyKey.signatureFor(record.alias)
            ?: return finishWithFailure(
                "This KyIdentity passkey is no longer usable. Enrol a new one from KyIdentity.",
            )

        VaultUnlockPrompt.showForSignature(
            activity = this,
            subtitle = "Sign in to KyIdentity",
            signature = signature,
            onAuthenticated = { authenticated ->
                val newSignCount = record.signCount + 1
                val authData = WebAuthnEngine.buildAssertionAuthData(record.rpId, newSignCount)
                val signed = runCatching {
                    WebAuthnEngine.signAssertion(authenticated, authData, clientDataHash)
                }.getOrNull()
                if (signed == null) {
                    finishWithFailure("Could not sign the challenge")
                    return@showForSignature
                }

                store.save(record.copy(signCount = newSignCount))

                val responseJson = JSONObject().apply {
                    put("id", b64(record.credentialId))
                    put("rawId", b64(record.credentialId))
                    put("type", "public-key")
                    put(
                        "response",
                        JSONObject().apply {
                            put("authenticatorData", b64(authData))
                            put("signature", b64(signed))
                            if (record.userHandle.isNotEmpty()) put("userHandle", b64(record.userHandle))
                            if (clientDataJson != null) put("clientDataJSON", b64(clientDataJson))
                        },
                    )
                }
                val data = Bundle().apply {
                    putString("androidx.credentials.BUNDLE_KEY_AUTHENTICATION_RESPONSE_JSON", responseJson.toString())
                }
                setResult(
                    RESULT_OK,
                    Intent().putExtra(
                        CredentialProviderService.EXTRA_GET_CREDENTIAL_RESPONSE,
                        GetCredentialResponse(Credential(TYPE_PUBLIC_KEY_CREDENTIAL, data)),
                    ),
                )
                finish()
            },
            onFailed = { finishWithCancellation() },
        )
    }

    /**
     * Enrols the KyIdentity passkey into secure hardware. Nothing here touches a vault key: that
     * independence is the point, so the factor works while KyAuth is locked.
     *
     * The new key goes into the spare alias. The stored record is replaced and the old key
     * deleted only once the new key has been generated and authenticated, so a cancelled prompt
     * leaves any existing passkey untouched; the response is assembled immediately after.
     */
    private fun createIdentityPasskey() {
        if (enrolling) return
        enrolling = true
        val requestJson = intent.getStringExtra(EXTRA_REQUEST_JSON).orEmpty()
        val json = runCatching { JSONObject(requestJson) }.getOrNull()
            ?: return finishWithFailure("Malformed passkey request")
        val rpId = intent.getStringExtra(EXTRA_RP_ID)?.takeIf { it.isNotBlank() }
            ?: return finishWithFailure("Request has no relying party")
        if (RpId.normalize(json.optJSONObject("rp")?.optString("id")) != rpId) {
            return finishWithFailure("Relying party does not match the request")
        }
        // EncryptedSharedPreferences can throw after a device restore or keyset invalidation; a
        // null here just means the RP cannot be confirmed as KyIdentity, and enrolment fails closed.
        val pairedServerUrl = runCatching { PairingStore(this).account()?.serverUrl }.getOrNull()
        if (!IdentityPasskey.isIdentityRpId(rpId, pairedServerUrl)) {
            return finishWithFailure("This relying party is not the paired KyIdentity server")
        }
        val challenge = json.optString("challenge").takeIf { it.isNotBlank() }
            ?: return finishWithFailure("Request has no challenge")

        val clientDataJson = if (intent.privilegedClientDataHash() != null) {
            null
        } else {
            val origin = intent.getStringExtra(EXTRA_ORIGIN)?.takeIf { it.isNotBlank() }
                ?: return finishWithFailure("Caller origin is unavailable")
            ClientData.serialize(
                ClientData.TYPE_CREATE,
                challenge,
                origin,
                intent.getStringExtra(EXTRA_CALLER_PACKAGE),
            )
        }

        val store = IdentityPasskeyStore(applicationContext)
        val live = store.record()
        val alias = IdentityPasskeyKey.spareAlias(live?.alias)
        val generated = runCatching { IdentityPasskeyKey.generate(alias) }.getOrElse {
            return finishWithFailure("This device cannot store a KyIdentity passkey in secure hardware")
        }
        val signature = IdentityPasskeyKey.signatureFor(alias) ?: run {
            IdentityPasskeyKey.delete(alias)
            return finishWithFailure("The new passkey could not be prepared")
        }

        VaultUnlockPrompt.showForSignature(
            activity = this,
            subtitle = "Create your KyIdentity passkey",
            signature = signature,
            onAuthenticated = { authenticated ->
                finishIdentityEnrolment(rpId, json, generated, live, store, clientDataJson, authenticated)
            },
            onFailed = { message ->
                // Roll back so a cancelled enrolment cannot strand the live key.
                IdentityPasskeyKey.delete(alias)
                Toast.makeText(applicationContext, message, Toast.LENGTH_SHORT).show()
                finishWithCancellation()
            },
        )
    }

    private fun finishIdentityEnrolment(
        rpId: String,
        json: JSONObject,
        generated: IdentityPasskeyKey.Generated,
        live: IdentityPasskeyRecord?,
        store: IdentityPasskeyStore,
        clientDataJson: ByteArray?,
        authenticated: Signature,
    ) {
        // Exercise the key once before the server is told it exists. The attestation is fmt:none
        // and carries no signature, so without this nothing ever proves the private key can sign;
        // a key that cannot would leave the server holding a credential no assertion can satisfy.
        // The probe bytes are thrown away and never leave this method.
        if (runCatching { WebAuthnEngine.signAssertion(authenticated, ENROLMENT_PROBE, ENROLMENT_PROBE) }.isFailure) {
            IdentityPasskeyKey.delete(generated.alias)
            return finishWithFailure("The new KyIdentity passkey could not sign; enrolment cancelled")
        }

        val userObj = json.optJSONObject("user")
        val fallbackUsername = userObj?.optString("name")?.ifBlank { null }
            ?: userObj?.optString("displayName")?.ifBlank { null }
            ?: intent.getStringExtra(EXTRA_USERNAME).orEmpty()
        val username = if (::usernameInput.isInitialized) {
            usernameInput.text.toString().trim()
        } else {
            fallbackUsername
        }

        val userHandleStr = userObj?.optString("id")
        val userHandle = if (!userHandleStr.isNullOrBlank()) {
            runCatching { Base64.decode(userHandleStr, B64_FLAGS) }
                .getOrDefault(userHandleStr.toByteArray(StandardCharsets.UTF_8))
        } else {
            ByteArray(0)
        }

        val credentialId = WebAuthnEngine.generateCredentialId()
        val authData = WebAuthnEngine.buildRegistrationAuthData(
            rpId = rpId,
            signCount = 0,
            credentialId = credentialId,
            cosePublicKey = WebAuthnEngine.encodeCosePublicKey(generated.publicKey),
        )
        val attestationObject = WebAuthnEngine.buildAttestationObject(authData)

        store.save(
            IdentityPasskeyRecord(
                rpId = rpId,
                username = username,
                userHandle = userHandle,
                credentialId = credentialId,
                signCount = 0,
                alias = generated.alias,
                strongBoxBacked = generated.strongBoxBacked,
            ),
        )
        // Only now is the previous key redundant.
        live?.alias?.takeIf { it != generated.alias }?.let(IdentityPasskeyKey::delete)

        val responseJson = JSONObject().apply {
            put("id", b64(credentialId))
            put("rawId", b64(credentialId))
            put("type", "public-key")
            put(
                "response",
                JSONObject().apply {
                    put("attestationObject", b64(attestationObject))
                    if (clientDataJson != null) put("clientDataJSON", b64(clientDataJson))
                },
            )
        }

        val data = Bundle().apply {
            putString("androidx.credentials.BUNDLE_KEY_REGISTRATION_RESPONSE_JSON", responseJson.toString())
        }
        setResult(
            RESULT_OK,
            Intent().putExtra(
                CredentialProviderService.EXTRA_CREATE_CREDENTIAL_RESPONSE,
                CreateCredentialResponse(data),
            ),
        )
        finish()
    }
    /**
     * The hash is honoured only alongside a privileged web origin. The service already refuses to
     * forward an unprivileged caller's hash; re-checking here keeps the rule with the code that
     * signs, so a future caller of this activity cannot reintroduce the bypass.
     */
    private fun Intent.privilegedClientDataHash(): ByteArray? =
        ClientData.privilegedClientDataHash(
            getStringExtra(EXTRA_ORIGIN),
            getByteArrayExtra(EXTRA_CLIENT_DATA_HASH),
        )

    private fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, B64_FLAGS)

    private fun finishWithFailure(message: String) {
        enrolling = false
        val result = Intent().apply {
            putExtra(CredentialProviderService.EXTRA_GET_CREDENTIAL_EXCEPTION, GetCredentialException("android.credentials.GetCredentialException.TYPE_UNKNOWN", message))
            putExtra(CredentialProviderService.EXTRA_CREATE_CREDENTIAL_EXCEPTION, CreateCredentialException("android.credentials.CreateCredentialException.TYPE_UNKNOWN", message))
        }
        setResult(RESULT_CANCELED, result)
        finish()
    }

    private fun finishWithCancellation() {
        // Every terminal exit clears the guard; a successful enrolment deliberately does not, so a
        // late tap cannot start a second one against a record that is already the server's.
        enrolling = false
        val result = Intent().apply {
            putExtra(CredentialProviderService.EXTRA_GET_CREDENTIAL_EXCEPTION, GetCredentialException("android.credentials.GetCredentialException.TYPE_USER_CANCELED", "User cancelled authentication"))
            putExtra(CredentialProviderService.EXTRA_CREATE_CREDENTIAL_EXCEPTION, CreateCredentialException("android.credentials.CreateCredentialException.TYPE_USER_CANCELED", "User cancelled creation"))
        }
        setResult(RESULT_CANCELED, result)
        finish()
    }

    companion object {
        const val ACTION_CREATE_IDENTITY_PASSKEY = "org.kysecurity.authenticator.action.CREATE_IDENTITY_PASSKEY"
        const val ACTION_GET_IDENTITY_PASSKEY = "org.kysecurity.authenticator.action.GET_IDENTITY_PASSKEY"

        const val EXTRA_ACTION = "extra_action"
        const val EXTRA_REQUEST_JSON = "extra_request_json"
        const val EXTRA_RP_ID = "extra_rp_id"
        const val EXTRA_USERNAME = "extra_username"
        const val EXTRA_DISPLAY_TITLE = "extra_display_title"
        const val EXTRA_DISPLAY_SUBTITLE = "extra_display_subtitle"
        const val EXTRA_ORIGIN = "extra_origin"
        const val EXTRA_CALLER_PACKAGE = "extra_caller_package"
        const val EXTRA_CLIENT_DATA_HASH = "extra_client_data_hash"

        private const val B64_FLAGS = Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP

        /** Throwaway bytes signed once at enrolment to prove the key works. Never sent anywhere. */
        private val ENROLMENT_PROBE = "kyauth-identity-enrolment-probe".toByteArray(StandardCharsets.UTF_8)

        const val TYPE_PUBLIC_KEY_CREDENTIAL = "android.credentials.TYPE_PUBLIC_KEY_CREDENTIAL"
    }
}
