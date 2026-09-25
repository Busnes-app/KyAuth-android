package org.kysecurity.authenticator.passkeys

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.KeyStore
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class IdentityPasskeyKeyTest {

    @After fun tearDown() = IdentityPasskeyKey.deleteAll()

    /**
     * Null when this device has no hardware-backed keystore — true of every Android emulator,
     * which ships the software KeyMint reference implementation. Callers assume past it rather
     * than failing, so a skipped result is never mistaken for a verified one.
     */
    private fun generateOrNull(alias: String): IdentityPasskeyKey.Generated? =
        try {
            IdentityPasskeyKey.generate(alias)
        } catch (expected: IdentityPasskeyKey.NoHardwareKeystore) {
            null
        }

    @Test
    fun generatesAHardwareBackedP256Key() {
        val generated = generateOrNull(IdentityPasskeyKey.ALIAS_A)
        assumeTrue("no hardware-backed keystore on this device", generated != null)
        assertEquals("EC", generated!!.publicKey.algorithm)
        assertEquals(256, generated.publicKey.params.curve.field.fieldSize)
    }

    @Test
    fun thePrivateKeyIsNotExportable() {
        val generated = generateOrNull(IdentityPasskeyKey.ALIAS_A)
        assumeTrue("no hardware-backed keystore on this device", generated != null)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val privateKey = keyStore.getKey(IdentityPasskeyKey.ALIAS_A, null)
        assertNotNull(privateKey)
        // A Keystore key never yields its bytes; this is the property the whole design rests on.
        assertNull(privateKey.encoded)
    }

    @Test
    fun spareAliasAlternatesSoEnrolmentNeverOverwritesALiveKey() {
        assertEquals(IdentityPasskeyKey.ALIAS_A, IdentityPasskeyKey.spareAlias(null))
        assertEquals(IdentityPasskeyKey.ALIAS_B, IdentityPasskeyKey.spareAlias(IdentityPasskeyKey.ALIAS_A))
        assertEquals(IdentityPasskeyKey.ALIAS_A, IdentityPasskeyKey.spareAlias(IdentityPasskeyKey.ALIAS_B))
    }

    @Test
    fun generatingTheSpareLeavesTheLiveKeyIntact() {
        val a = generateOrNull(IdentityPasskeyKey.ALIAS_A)
        assumeTrue("no hardware-backed keystore on this device", a != null)
        val b = generateOrNull(IdentityPasskeyKey.ALIAS_B)
        assumeTrue("no hardware-backed keystore on this device", b != null)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue(keyStore.containsAlias(IdentityPasskeyKey.ALIAS_A))
        assertTrue(keyStore.containsAlias(IdentityPasskeyKey.ALIAS_B))
    }

    @Test
    fun deleteRemovesOnlyTheNamedAlias() {
        val a = generateOrNull(IdentityPasskeyKey.ALIAS_A)
        assumeTrue("no hardware-backed keystore on this device", a != null)
        val b = generateOrNull(IdentityPasskeyKey.ALIAS_B)
        assumeTrue("no hardware-backed keystore on this device", b != null)
        IdentityPasskeyKey.delete(IdentityPasskeyKey.ALIAS_A)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue(!keyStore.containsAlias(IdentityPasskeyKey.ALIAS_A))
        assertTrue(keyStore.containsAlias(IdentityPasskeyKey.ALIAS_B))
    }

    @Test
    fun signatureForAnAbsentAliasIsNull() {
        assertNull(IdentityPasskeyKey.signatureFor(IdentityPasskeyKey.ALIAS_A))
    }

    @Test
    fun refusesASoftwareBackedKeyAndDoesNotLeaveItBehind() {
        // A software-backed key would be exportable, which is the property this class exists to
        // remove. On a device without hardware backing, generate() must throw AND must not leave
        // the rejected key sitting in the keystore for something else to pick up.
        val error = runCatching { IdentityPasskeyKey.generate(IdentityPasskeyKey.ALIAS_A) }.exceptionOrNull()
        assumeTrue("this device has hardware backing, so the fail-closed path cannot run here", error != null)
        assertTrue(
            "expected NoHardwareKeystore, got ${error!!::class.java.name}",
            error is IdentityPasskeyKey.NoHardwareKeystore,
        )
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse(keyStore.containsAlias(IdentityPasskeyKey.ALIAS_A))
    }
}
