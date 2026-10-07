package org.kysecurity.authenticator.security

import android.content.Context
import org.kysecurity.authenticator.pairing.DeviceSigningKey
import org.kysecurity.authenticator.pairing.PairingStore
import java.security.KeyStore

object SecurityWipe {
    fun wipe(context: Context) {
        // 1. Wipe PairingStore and the KyIdentity passkey record
        runCatching { org.kysecurity.authenticator.signon.KyIdentityAccount.remove(context) }
        runCatching { PairingStore(context).clear() }
        runCatching { org.kysecurity.authenticator.passkeys.IdentityPasskeyStore(context).clear() }
        // Prefs files: current, then legacy encrypted ones and the KyPasswords session file.
        PREFS_FILES.forEach { runCatching { context.deleteSharedPreferences(it) } }

        // 2. Wipe AppLock SharedPreferences
        runCatching {
            context.getSharedPreferences("app_lock", Context.MODE_PRIVATE)
                .edit()
                .clear()
                .commit()
        }

        // 3. Wipe all app files (including KDBX vaults)
        runCatching {
            context.filesDir.listFiles()?.forEach { file ->
                file.deleteRecursively()
            }
        }

        // 4. Wipe cached files
        runCatching {
            context.cacheDir.listFiles()?.forEach { file ->
                file.deleteRecursively()
            }
        }

        // 5. Delete Keystore signing key and peppers
        runCatching { DeviceSigningKey.deleteKey() }
        runCatching {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            keyStore.deleteEntry(ANDROIDX_MASTER_KEY)
            val aliases = keyStore.aliases()
            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                if (isAppAlias(alias)) {
                    keyStore.deleteEntry(alias)
                }
            }
        }

        // 6. Reset in-memory state
        AppLockManager.onWipe()
    }

    private const val ANDROIDX_MASTER_KEY = "_androidx_security_master_key_"

    private val PREFS_FILES = listOf(
        "pairing_store", "identity_passkey_store", "pairing", "identity_passkey",
        "kypasswords_pairing", "mfa_push_challenge", "push",
    )

    /**
     * KyAuth's own AndroidKeyStore entries, matched without pinning a separator: the aliases in use
     * are a mix of `kyauth_`, `kysignon-`, and `kyidentity-`, and requiring one spelling silently left
     * [DeviceSigningKey]'s key behind. androidx's master key is deleted by name in step 5;
     * older builds used it for encrypted prefs.
     */
    internal fun isAppAlias(alias: String): Boolean =
        alias.startsWith("kyauth") || alias.startsWith("kysignon") || alias.startsWith("kyidentity")
}
