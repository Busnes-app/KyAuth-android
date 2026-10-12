package org.kysecurity.authenticator.pairing

/** Where KyIdentity sends this device's pushes. `p256dh`/`auth` are the RFC 8291 keys (UnifiedPush only). */
data class PushCredential(
    val transport: String,
    val token: String,
    val p256dh: String? = null,
    val auth: String? = null,
) {
    init {
        require(transport == FCM || transport == UNIFIED_PUSH) { "Unknown push transport" }
        require(token.isNotBlank()) { "Push token is required" }
        require((transport == UNIFIED_PUSH) == (!p256dh.isNullOrBlank() && !auth.isNullOrBlank())) {
            "UnifiedPush needs its encryption keys; FCM carries none"
        }
    }

    // The token and keys address and decrypt this device's pushes: never log them.
    override fun toString(): String = "PushCredential(transport=$transport, token=<redacted>)"

    companion object {
        const val FCM = "fcm"
        const val UNIFIED_PUSH = "unifiedpush"
    }
}
