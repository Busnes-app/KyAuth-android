package org.kysecurity.authenticator.mfa

import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import org.kysecurity.authenticator.pairing.PairingStore
import org.kysecurity.authenticator.pairing.PushCredential
import org.kysecurity.authenticator.pairing.PushStore

class KyAuthMessagingService : FirebaseMessagingService() {
    override fun onNewToken(token: String) {
        val paired = PairingStore(this).account() != null
        if (PushStore(this).tokenChanged(paired, PushCredential(PushCredential.FCM, token))) IncomingPush.notifyReconnect(this)
    }

    override fun onMessageReceived(message: RemoteMessage) = IncomingPush.handle(this, message.data)
}
