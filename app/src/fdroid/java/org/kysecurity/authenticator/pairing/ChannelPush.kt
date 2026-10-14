package org.kysecurity.authenticator.pairing

/** fdroid ships no Firebase; UnifiedPush is the only transport. */
object ChannelPush {
    fun fcmCredential(): Result<PushCredential> =
        Result.failure(IllegalStateException("This build has no Firebase; use UnifiedPush"))

    fun resume() = Unit

    fun forget() = Unit
}
