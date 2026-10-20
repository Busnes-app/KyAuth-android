package org.kysecurity.authenticator.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Seals the FCM push keys at rest under a Keystore AES-256-GCM key, as the UnifiedPush connector
 * does its own WebPush keys. Not bound to authentication or an unlocked device: pushes arrive and
 * are opened while the phone is locked. The wipe's prefix sweep deletes the alias.
 */
object PushKeyWrap {
    internal const val ALIAS = "kyauth_fcm_push_keys"
    private val AAD = "kyauth-fcm-push-keys-v1".toByteArray(Charsets.UTF_8)

    fun seal(plain: ByteArray): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, key())
            updateAAD(AAD)
        }
        return WrappedSecret(cipher.iv, cipher.doFinal(plain)).serialize()
    }

    fun open(sealed: String): ByteArray {
        val wrapped = requireNotNull(WrappedSecret.deserialize(sealed)) { "Malformed push keys" }
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = keyStore.getKey(ALIAS, null) as SecretKey
        return Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, wrapped.iv))
            updateAAD(AAD)
            doFinal(wrapped.ciphertext)
        }
    }

    private fun key(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(
                KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build(),
            )
        }.generateKey()
    }
}
