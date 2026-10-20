package org.kysecurity.authenticator.mfa

import android.util.Log
import org.kysecurity.authenticator.pairing.PairingStore
import org.kysecurity.authenticator.pairing.PushCredential
import org.kysecurity.authenticator.pairing.PushStore
import org.unifiedpush.android.connector.FailedReason
import org.unifiedpush.android.connector.PushService
import org.unifiedpush.android.connector.data.PushEndpoint
import org.unifiedpush.android.connector.data.PushMessage

class KyAuthUnifiedPushService : PushService() {
    override fun onNewEndpoint(endpoint: PushEndpoint, instance: String) {
        // Without RFC 8291 keys KyIdentity refuses the endpoint, so there is nothing to save.
        val keys = endpoint.pubKeySet ?: return
        val credential = runCatching { PushCredential(PushCredential.UNIFIED_PUSH, endpoint.url, keys.pubKey, keys.auth) }.getOrNull() ?: return
        // Saved even when unpaired: the first pairing needs it.
        val paired = PairingStore(this).account() != null
        if (PushStore(this).tokenChanged(paired, credential)) IncomingPush.notifyReconnect(this)
    }

    override fun onMessage(message: PushMessage, instance: String) {
        if (!message.decrypted) {
            Log.w(TAG, "Dropping UnifiedPush message that did not decrypt")
            return
        }
        IncomingPush.handle(this, IncomingPush.jsonData(message.content) ?: return)
    }

    override fun onRegistrationFailed(reason: FailedReason, instance: String) =
        broken("UnifiedPush registration failed ($reason).")

    override fun onUnregistered(instance: String) =
        broken("Your UnifiedPush distributor stopped delivering to KyAuth.")

    // Never fall back silently: the user sees this until they reconnect.
    private fun broken(reason: String) {
        val store = PushStore(this)
        if (store.transport == PushCredential.UNIFIED_PUSH) store.markBroken(reason)
    }

    private companion object {
        const val TAG = "KyAuthUnifiedPushService"
    }
}
