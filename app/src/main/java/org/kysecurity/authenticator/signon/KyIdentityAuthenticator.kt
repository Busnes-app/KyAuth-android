package org.kysecurity.authenticator.signon

import android.accounts.AbstractAccountAuthenticator
import android.accounts.Account
import android.accounts.AccountAuthenticatorResponse
import android.accounts.AccountManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import org.kysecurity.authenticator.MainActivity
import org.kysecurity.authenticator.pairing.PairedAccount
import org.kysecurity.authenticator.pairing.PairingStore

sealed class SignOnRequest {
    data class Proceed(val caller: TrustedCaller, val clientId: String, val origin: String, val paired: PairedAccount) : SignOnRequest()
    data class Refuse(val code: Int, val message: String) : SignOnRequest()
}

/** Everything that decides whether a token request may reach the prompt, with no Android state. */
internal fun decideSignOn(caller: TrustedCaller?, authTokenType: String?, rawOrigin: String?, paired: PairedAccount?): SignOnRequest {
    if (caller == null) return SignOnRequest.Refuse(AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION, "This app is not allowed to use KyIdentity sign-in")
    if (!DeviceAssertion.isValidClientId(authTokenType)) return SignOnRequest.Refuse(AccountManager.ERROR_CODE_BAD_ARGUMENTS, "Invalid client id")
    val origin = DeviceAssertion.relayOrigin(rawOrigin)
        ?: return SignOnRequest.Refuse(AccountManager.ERROR_CODE_BAD_ARGUMENTS, "A secure relay address is required")
    if (paired == null || paired.userId.isNullOrBlank()) {
        return SignOnRequest.Refuse(AccountManager.ERROR_CODE_BAD_REQUEST, "Pair KyAuth with KyIdentity first.")
    }
    if (!paired.canSignOn) {
        return SignOnRequest.Refuse(AccountManager.ERROR_CODE_BAD_REQUEST, "Sign-in was not enabled for this phone when it was paired. Pair KyAuth again after enabling sign-in on the KyIdentity devices page.")
    }
    return SignOnRequest.Proceed(caller, authTokenType!!, origin, paired)
}

/** Stale-account cleanup only when the pairing read succeeded and it says "not paired / sign-on off". */
internal fun cleanupAfterRefusal(readSucceeded: Boolean, decision: SignOnRequest): Boolean =
    readSucceeded && decision is SignOnRequest.Refuse && decision.code == AccountManager.ERROR_CODE_BAD_REQUEST

/** `getAuthToken` option carrying the relay URL the consumer's user typed. */
const val ORIGIN_OPTION = "org.kysecurity.identity.origin"

/**
 * Account authenticator for `org.kysecurity.identity`. `customTokens` is on, so the system never
 * caches what this returns and every request arrives with the caller's UID.
 */
class KyIdentityAuthenticator(private val context: Context) : AbstractAccountAuthenticator(context) {

    override fun addAccount(
        response: AccountAuthenticatorResponse?,
        accountType: String?,
        authTokenType: String?,
        requiredFeatures: Array<out String>?,
        options: Bundle?,
    ): Bundle {
        val intent = Intent(context, MainActivity::class.java)
            .putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response)
        return Bundle().apply { putParcelable(AccountManager.KEY_INTENT, intent) }
    }

    override fun getAuthToken(
        response: AccountAuthenticatorResponse?,
        account: Account?,
        authTokenType: String?,
        options: Bundle?,
    ): Bundle {
        val uid = options?.getInt(AccountManager.KEY_CALLER_UID, -1) ?: -1
        val caller = if (uid > 0) TrustedConsumers.isTrusted(context, uid) else null
        val read = runCatching { PairingStore(context).account() }
        if (read.isFailure) return error(AccountManager.ERROR_CODE_REMOTE_EXCEPTION, "KyAuth could not read its pairing; try again")
        val paired = read.getOrNull()
        return when (val decision = decideSignOn(caller, authTokenType, options?.getString(ORIGIN_OPTION), paired)) {
            is SignOnRequest.Refuse -> {
                if (cleanupAfterRefusal(true, decision)) runCatching { KyIdentityAccount.sync(context, paired) }
                error(decision.code, decision.message)
            }
            is SignOnRequest.Proceed -> {
                val intent = Intent(context, SignOnActivity::class.java)
                    .putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response)
                    .putExtra(SignOnActivity.EXTRA_REQUEST, PendingSignOn.issue(decision))
                Bundle().apply { putParcelable(AccountManager.KEY_INTENT, intent) }
            }
        }
    }

    override fun getAuthTokenLabel(authTokenType: String?): String = "KyIdentity sign-in"

    override fun hasFeatures(response: AccountAuthenticatorResponse?, account: Account?, features: Array<out String>?): Bundle =
        Bundle().apply { putBoolean(AccountManager.KEY_BOOLEAN_RESULT, !features.isNullOrEmpty() && features.all { it == "signon" }) }

    override fun getAccountRemovalAllowed(response: AccountAuthenticatorResponse?, account: Account?): Bundle =
        Bundle().apply { putBoolean(AccountManager.KEY_BOOLEAN_RESULT, true) }

    override fun editProperties(response: AccountAuthenticatorResponse?, accountType: String?): Bundle = error(AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION, "Not supported")
    override fun confirmCredentials(response: AccountAuthenticatorResponse?, account: Account?, options: Bundle?): Bundle = error(AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION, "Not supported")
    override fun updateCredentials(response: AccountAuthenticatorResponse?, account: Account?, authTokenType: String?, options: Bundle?): Bundle = error(AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION, "Not supported")

    private fun error(code: Int, message: String) = Bundle().apply {
        putInt(AccountManager.KEY_ERROR_CODE, code)
        putString(AccountManager.KEY_ERROR_MESSAGE, message)
    }
}
