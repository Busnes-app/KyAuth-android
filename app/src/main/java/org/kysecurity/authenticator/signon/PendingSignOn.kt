package org.kysecurity.authenticator.signon

import android.accounts.AccountAuthenticatorResponse
import java.util.Base64
import java.security.SecureRandom

/** One-shot, short-lived handoff from the authenticator to an exported activity. */
open class OneShot<T : Any> {
    private val ttlMs = 120_000L
    private val random = SecureRandom()
    private val pending = HashMap<String, Pair<Long, T>>()
    internal var clock: () -> Long = System::currentTimeMillis

    @Synchronized
    fun issue(value: T): String {
        prune()
        val bytes = ByteArray(32).also(random::nextBytes)
        val nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        pending[nonce] = clock() + ttlMs to value
        return nonce
    }

    @Synchronized
    fun take(nonce: String?): T? {
        prune()
        return nonce?.let { pending.remove(it)?.second }
    }

    private fun prune() {
        val now = clock()
        pending.values.removeAll { it.first <= now }
    }
}

object PendingSignOn : OneShot<SignOnRequest.Proceed>()

/** The addAccount response, so an intent extra from a forged launch is never answered. */
object PendingAddAccount : OneShot<AccountAuthenticatorResponse>()
