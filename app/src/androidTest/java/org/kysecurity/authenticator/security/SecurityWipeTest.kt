package org.kysecurity.authenticator.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import javax.crypto.KeyGenerator

@RunWith(AndroidJUnit4::class)
class SecurityWipeTest {

    @Test
    fun securityWipeClearsEveryPrefsFileAndTheMasterKey() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val names = listOf(
            "mfa_push_challenge", "push", "pairing", "identity_passkey", "identity_passkey_store",
            "pairing_store", "kypasswords_pairing",
        )
        names.forEach { context.getSharedPreferences(it, Context.MODE_PRIVATE).edit().putString("k", "v").commit() }
        val masterAlias = "_androidx_security_master_key_"
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(
                KeyGenParameterSpec.Builder(
                    masterAlias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build(),
            )
        }.generateKey()
        assertTrue(KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.containsAlias(masterAlias))
        SecurityWipe.wipe(context)
        names.forEach {
            assertFalse("$it survived", context.getSharedPreferences(it, Context.MODE_PRIVATE).contains("k"))
        }
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse(keyStore.containsAlias(masterAlias))
    }
}
