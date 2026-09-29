package org.kysecurity.authenticator.signon

import java.util.Base64
import java.security.SecureRandom

/** One-shot, short-lived handoff from the authenticator to the exported sign-on activity. */
object PendingSignOn {
    private const val TTL_MS = 120_000L
    private val random = SecureRandom()
    private val pending = HashMap<String, Pair<Long, SignOnRequest.Proceed>>()
    internal var clock: () -> Long = System::currentTimeMillis

    @Synchronized
    fun issue(request: SignOnRequest.Proceed): String {
        prune()
        val bytes = ByteArray(32).also(random::nextBytes)
        val nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        pending[nonce] = clock() + TTL_MS to request
        return nonce
    }

    @Synchronized
    fun take(nonce: String?): SignOnRequest.Proceed? {
        prune()
        return nonce?.let { pending.remove(it)?.second }
    }

    private fun prune() {
        val now = clock()
        pending.values.removeAll { it.first <= now }
    }
}
