package org.kysecurity.authenticator.pairing

/**
 * Where KyIdentity sends this device's pushes. `p256dh`/`auth` are the RFC 8291 keys: required for
 * UnifiedPush, and on FCM both or neither (a pairing made before KyAuth sent them has none).
 */
data class PushCredential(
    val transport: String,
    val token: String,
    val p256dh: String? = null,
    val auth: String? = null,
) {
    init {
        require(transport == FCM || transport == UNIFIED_PUSH) { "Unknown push transport" }
        require(token.isNotBlank()) { "Push token is required" }
        val keys = !p256dh.isNullOrBlank() && !auth.isNullOrBlank()
        require(keys || (p256dh == null && auth == null)) { "Push keys are both or neither" }
        require(transport == FCM || keys) { "UnifiedPush needs its encryption keys" }
    }

    /** This FCM credential sealed to [keys] (or keyless, for null). */
    fun withKeys(keys: PushKeys?): PushCredential = copy(p256dh = keys?.p256dh, auth = keys?.auth)

    // The token and keys address and decrypt this device's pushes: never log them.
    override fun toString(): String = "PushCredential(transport=$transport, token=<redacted>)"

    companion object {
        const val FCM = "fcm"
        const val UNIFIED_PUSH = "unifiedpush"
    }
}
