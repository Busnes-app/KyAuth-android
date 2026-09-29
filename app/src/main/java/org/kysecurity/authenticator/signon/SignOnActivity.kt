package org.kysecurity.authenticator.signon

import android.accounts.AccountAuthenticatorResponse
import android.accounts.AccountManager
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.net.URI
import java.security.Signature
import java.util.UUID
import org.kysecurity.authenticator.BuildConfig
import org.kysecurity.authenticator.R
import org.kysecurity.authenticator.ThemeManager
import org.kysecurity.authenticator.pairing.DeviceSigningKey
import org.kysecurity.authenticator.pairing.PairingStore
import org.kysecurity.authenticator.parcelable
import org.kysecurity.authenticator.security.VaultUnlockPrompt

/**
 * "App wants to sign in as alice". One biometric, one assertion, one token, delivered to the
 * caller through the authenticator response. Touches no vault key.
 */
class SignOnActivity : AppCompatActivity() {
    companion object {
        const val EXTRA_REQUEST = "request"
    }

    private var response: AccountAuthenticatorResponse? = null
    private var delivered = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!BuildConfig.ALLOW_SCREENSHOTS) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        response = intent.parcelable(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE)
        // A forged or replayed launch has no nonce: learn nothing, touch nothing.
        val request = PendingSignOn.take(intent.getStringExtra(EXTRA_REQUEST))
        if (request == null) {
            delivered = true
            response?.onError(AccountManager.ERROR_CODE_CANCELED, "Sign-in request expired")
            finish()
            return
        }
        val read = runCatching { PairingStore(this).account() }
        if (read.isFailure) {
            fail(AccountManager.ERROR_CODE_REMOTE_EXCEPTION, "KyAuth could not read its pairing; try again")
            return
        }
        val paired = read.getOrNull()
        if (paired == null || !paired.canSignOn || paired.userId.isNullOrBlank()) {
            fail(AccountManager.ERROR_CODE_BAD_REQUEST, "Pair KyAuth with KyIdentity first.")
            return
        }
        render(request.copy(paired = paired))
    }

    private fun render(request: SignOnRequest.Proceed) {
        val density = resources.displayMetrics.density
        val host = runCatching { URI(request.paired.serverUrl).host }.getOrNull() ?: request.paired.serverUrl
        val who = request.paired.username ?: request.paired.userId
        val pad = (24 * density).toInt()
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad * 3, pad, pad)
            setBackgroundColor(ThemeManager.color(context, R.color.ky_background))
        }
        root.addView(TextView(this).apply {
            text = getString(R.string.signon_prompt, request.caller.label, who, host)
            textSize = 18f
            setTextColor(ThemeManager.color(context, R.color.ky_heading))
        })
        root.addView(button(R.string.signon_approve, R.color.ky_cyan, ThemeManager.buttonText(this)) { it.isEnabled = false; approve(request) })
        root.addView(button(R.string.signon_deny, R.color.ky_surface_elevated, ThemeManager.color(this, R.color.ky_muted)) {
            fail(AccountManager.ERROR_CODE_CANCELED, "Sign-in denied")
        })
        setContentView(root)
    }

    private fun button(label: Int, bg: Int, fg: Int, onClick: (Button) -> Unit) = Button(this).apply {
        val density = resources.displayMetrics.density
        text = getString(label)
        setTextColor(fg)
        background = GradientDrawable().apply {
            setColor(ThemeManager.color(context, bg))
            cornerRadius = 14 * density
        }
        setOnClickListener { onClick(this) }
        filterTouchesWhenObscured = true
        layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, (48 * density).toInt())
            .apply { topMargin = (16 * density).toInt() }
    }

    private fun approve(request: SignOnRequest.Proceed) {
        val signature = runCatching { DeviceSigningKey.initSignature() }.getOrElse {
            fail(AccountManager.ERROR_CODE_REMOTE_EXCEPTION, "The device key is unavailable. Re-pair KyAuth.")
            return
        }
        VaultUnlockPrompt.showForSignature(
            activity = this,
            subtitle = getString(R.string.signon_biometric_subtitle, request.caller.label),
            signature = signature,
            onAuthenticated = { authed -> signAndRedeem(request, authed) },
            onFailed = { fail(AccountManager.ERROR_CODE_CANCELED, "Authentication was cancelled") },
        )
    }

    private fun signAndRedeem(request: SignOnRequest.Proceed, authed: Signature) {
        val paired = request.paired
        val input = DeviceAssertion.signingInput(
            deviceId = paired.deviceId,
            userId = paired.userId.orEmpty(),
            serverUrl = paired.serverUrl,
            clientId = request.clientId,
            nowEpochSeconds = System.currentTimeMillis() / 1000,
            jti = UUID.randomUUID().toString(),
        )
        val assertion = runCatching {
            authed.update(input.toByteArray())
            DeviceAssertion.compact(input, DeviceAssertion.derToRaw(authed.sign()))
        }.getOrElse {
            fail(AccountManager.ERROR_CODE_REMOTE_EXCEPTION, "Could not sign the sign-in request")
            return
        }
        Thread {
            val result = TokenClient().redeem(paired.serverUrl, request.clientId, assertion)
            runOnUiThread {
                when (result) {
                    is TokenResult.Success -> deliver(result)
                    is TokenResult.Failure -> {
                        fail(AccountManager.ERROR_CODE_REMOTE_EXCEPTION, result.userMessage)
                    }
                }
            }
        }.start()
    }

    private fun deliver(result: TokenResult.Success) {
        if (delivered) return
        // No expiry on purpose: with customTokens the system would cache this token per caller, and its jti is single-use.
        val bundle = Bundle().apply {
            putString(AccountManager.KEY_ACCOUNT_NAME, KyIdentityAccount.current(this@SignOnActivity)?.name)
            putString(AccountManager.KEY_ACCOUNT_TYPE, KyIdentityAccount.TYPE)
            putString(AccountManager.KEY_AUTHTOKEN, result.idToken)
        }
        delivered = true
        response?.onResult(bundle)
        finish()
    }

    private fun fail(code: Int, message: String) {
        if (!delivered) {
            delivered = true
            response?.onError(code, message)
        }
        finish()
    }

    override fun onDestroy() {
        if (!delivered) {
            delivered = true
            response?.onError(AccountManager.ERROR_CODE_CANCELED, "Sign-in cancelled")
        }
        super.onDestroy()
    }
}
