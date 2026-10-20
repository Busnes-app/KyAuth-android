package org.kysecurity.authenticator.mfa

/** The text of the pending request card, kept out of MainActivity so it is unit-tested. */
object RequestCardText {
    /**
     * The account the request is for: the username in the push (sealed only, from KyIdentity), else
     * the one saved at pairing. Null when neither exists; the card then names no account, and never
     * puts the phone's own name in its place.
     */
    fun account(challenge: MfaChallenge, pairedUsername: String?): String? =
        challenge.username?.trim()?.takeIf { it.isNotEmpty() } ?: pairedUsername?.trim()?.takeIf { it.isNotEmpty() }

    /** `host[:port]` of the server, by the same rule as the signed origin; the trimmed URL if it has no host. */
    fun server(serverUrl: String): String =
        runCatching { MfaMessage.origin(serverUrl).substringAfter("://") }.getOrDefault(serverUrl.trim())

    /** "Expires in m:ss" while [secondsRemaining] is positive, then "Expired". */
    fun expiry(secondsRemaining: Long): String =
        if (secondsRemaining <= 0) "Expired" else "Expires in ${secondsRemaining / 60}:${(secondsRemaining % 60).toString().padStart(2, '0')}"

    /** The account and server lines above the countdown. */
    fun details(challenge: MfaChallenge, pairedUsername: String?): String =
        listOfNotNull(account(challenge, pairedUsername)?.let { "Account: $it" }, "Server: ${server(challenge.serverUrl)}")
            .joinToString("\n")
}
