package org.kysecurity.authenticator.pairing

/** play and github: Firebase. */
object ChannelPush {
    fun fcmCredential(): Result<PushCredential> =
        PushTokenProvider.currentToken().map { PushCredential(PushCredential.FCM, it) }
}
