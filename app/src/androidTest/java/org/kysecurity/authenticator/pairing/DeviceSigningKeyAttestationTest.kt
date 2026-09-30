package org.kysecurity.authenticator.pairing

import android.app.KeyguardManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

@RunWith(AndroidJUnit4::class)
class DeviceSigningKeyAttestationTest {
    private val keyAttestationOid = "1.3.6.1.4.1.11129.2.1.17"

    @Before
    fun requireSecureLock() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assumeTrue(context.getSystemService(KeyguardManager::class.java).isDeviceSecure)
    }

    @After fun tearDown() = DeviceSigningKey.deleteKey()

    @Test
    fun regenerate_returnsChainWhoseLeafMatchesPublicKey() {
        val generated = DeviceSigningKey.regenerate(ByteArray(32) { it.toByte() })
        assertTrue("chain expected on any KeyMint device", generated.attestationChain.isNotEmpty())
        val cf = CertificateFactory.getInstance("X.509")
        val leaf = cf.generateCertificate(
            ByteArrayInputStream(Base64.getDecoder().decode(generated.attestationChain[0])),
        ) as X509Certificate
        assertNotNull("leaf carries the attestation extension", leaf.getExtensionValue(keyAttestationOid))
        assertEquals(generated.publicKeyBase64, Base64.getEncoder().encodeToString(leaf.publicKey.encoded))
        assertEquals(generated.publicKeyBase64, DeviceSigningKey.publicKeyBase64())
    }

    @Test
    fun regenerate_replacesThePreviousKey() {
        val a = DeviceSigningKey.regenerate(ByteArray(32) { 1 })
        val b = DeviceSigningKey.regenerate(ByteArray(32) { 2 })
        assertNotEquals(a.publicKeyBase64, b.publicKeyBase64)
        assertEquals(b.publicKeyBase64, DeviceSigningKey.publicKeyBase64())
    }
}
