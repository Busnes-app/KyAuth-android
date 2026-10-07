package org.kysecurity.authenticator.mfa

data class MfaChallenge(
    val challengeId: String,
    val matchDigits: String = "",
    val decoyDigits: List<String>,
    val serverUrl: String,
    val username: String? = null,
    val purpose: String,
    val expiresAtEpochMs: Long,
) {
    init {
        require(challengeId.isNotBlank()) { "Challenge ID is required" }
        require(serverUrl.isNotBlank()) { "Server URL is required" }
    }

    /**
     * Returns the 4 distinct 2-digit candidate numbers (the match and 3 decoys)
     * in a deterministic shuffled order for display in the grid.
     */
    fun options(): List<String> {
        val all = (listOf(matchDigits) + decoyDigits).filter { it.isNotBlank() }.distinct()
        return all.sorted()
    }
}

object MfaMessage {
    // Wire contract: must equal what KyIdentity's internal/mfa PushResponseMessage builds.
    private const val PREFIX = "kyidentity-push-v2"
    internal val PUSH_PURPOSES = setOf("login", "step_up")

    /** scheme://host[:port], lowercased, default port dropped; the same rule KyIdentity uses. */
    fun origin(serverUrl: String): String {
        val uri = runCatching { java.net.URI(serverUrl.trim()) }.getOrNull()
        val scheme = uri?.scheme?.lowercase()
        val host = uri?.host?.lowercase()
        require(scheme != null && !host.isNullOrBlank()) { "Server URL has no origin" }
        val port = uri.port.takeUnless { it == -1 || (scheme == "https" && it == 443) || (scheme == "http" && it == 80) }
        return if (port == null) "$scheme://$host" else "$scheme://$host:$port"
    }

    /** The exact bytes the device key signs to answer a challenge; see the push v2 spec. */
    fun formatPayload(
        origin: String, userId: String, deviceId: String, challengeId: String,
        purpose: String, expiresAtMs: Long, approve: Boolean, selectedDigits: String,
    ): ByteArray {
        require(purpose in PUSH_PURPOSES) { "Unknown push purpose" }
        for (field in listOf(origin, userId, deviceId, challengeId)) {
            require(field.isNotEmpty() && '|' !in field) { "Invalid push binding field" }
        }
        require('|' !in selectedDigits) { "Invalid digits" }
        val verb = if (approve) "approve" else "deny"
        return listOf(PREFIX, origin, userId, deviceId, challengeId, purpose, expiresAtMs.toString(), verb, selectedDigits)
            .joinToString("|").toByteArray(Charsets.UTF_8)
    }
}
