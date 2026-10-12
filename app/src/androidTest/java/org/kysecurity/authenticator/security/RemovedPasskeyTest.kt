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
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec

@RunWith(AndroidJUnit4::class)
class RemovedPasskeyTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()

    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    @Test
    fun deletesEveryKeyAndPrefsFileAndIsSafeToRepeat() {
        RemovedPasskey.ALIASES.forEach { alias ->
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
                initialize(
                    KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .build(),
                )
            }.generateKeyPair()
        }
        RemovedPasskey.PREFS.forEach {
            context.getSharedPreferences(it, Context.MODE_PRIVATE).edit().putString("record", "x").commit()
        }
        RemovedPasskey.ALIASES.forEach { assertTrue(keyStore().containsAlias(it)) }

        RemovedPasskey.delete(context)
        RemovedPasskey.delete(context)

        RemovedPasskey.ALIASES.forEach { assertFalse("$it survived", keyStore().containsAlias(it)) }
        RemovedPasskey.PREFS.forEach {
            assertFalse("$it survived", context.getSharedPreferences(it, Context.MODE_PRIVATE).contains("record"))
        }
    }
}
