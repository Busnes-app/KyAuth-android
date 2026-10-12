package org.kysecurity.authenticator.security

import android.content.Context
import java.security.KeyStore

/**
 * Earlier builds held a KyIdentity passkey. Deletes its keys and metadata; safe to run on every
 * start and when nothing is there.
 */
object RemovedPasskey {
    // The alternating pair, and the pair from before the KySignOn -> KyIdentity rename.
    internal val ALIASES = listOf(
        "kyauth_identity_passkey_a", "kyauth_identity_passkey_b",
        "kyauth_signon_passkey_a", "kyauth_signon_passkey_b",
    )
    internal val PREFS = listOf("identity_passkey_store", "identity_passkey")

    fun delete(context: Context) {
        runCatching {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            ALIASES.forEach { alias -> runCatching { if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias) } }
        }
        PREFS.forEach { runCatching { context.deleteSharedPreferences(it) } }
    }
}
