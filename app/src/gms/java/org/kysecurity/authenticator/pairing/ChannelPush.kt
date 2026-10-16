package org.kysecurity.authenticator.pairing

import com.google.firebase.messaging.FirebaseMessaging

/** play and github: Firebase. */
object ChannelPush {
    fun fcmCredential(): Result<PushCredential> =
        PushTokenProvider.currentToken().map { PushCredential(PushCredential.FCM, it) }

    /** A device paired over FCM before auto-init was off by default keeps its token rotating. */
    fun resume() {
        runCatching { FirebaseMessaging.getInstance().isAutoInitEnabled = true }
    }

    /** Deletes the FCM token and keeps Firebase from minting another until [fcmCredential]. */
    fun forget() {
        runCatching {
            FirebaseMessaging.getInstance().apply {
                isAutoInitEnabled = false
                deleteToken()
            }
        }
    }
}
