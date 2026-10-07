package org.kysecurity.authenticator.pairing

import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

class DeviceSigningKeyTest {
    @Before
    fun setup() {
        val keyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        DeviceSigningKey.setTestKeyPair(keyPair)
    }

    @After
    fun teardown() {
        DeviceSigningKey.setTestKeyPair(null)
    }

    @Test
    fun generatesValidP256PublicKey() {
        val pubB64 = DeviceSigningKey.publicKeyBase64()
        assertNotNull(pubB64)
        val decoded = Base64.getDecoder().decode(pubB64)
        assertTrue(decoded.isNotEmpty())
    }

    @Test
    fun signsMessageAndVerifiesCorrectly() {
        val message = "kyidentity-push-v2|https://id.example.com|u-123|d-456|c-789|login|1791331200000|approve|42".toByteArray(Charsets.UTF_8)
        val signatureB64 = DeviceSigningKey.sign(message)
        assertNotNull(signatureB64)

        val sigBytes = Base64.getDecoder().decode(signatureB64)
        val keyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        // Verify with the test public key
        val pubBytes = Base64.getDecoder().decode(DeviceSigningKey.publicKeyBase64())
        val keyFactory = KeyFactory.getInstance("EC")
        val pubKey = keyFactory.generatePublic(X509EncodedKeySpec(pubBytes))

        val verifier = Signature.getInstance("SHA256withECDSA").apply {
            initVerify(pubKey)
            update(message)
        }
        assertTrue(verifier.verify(sigBytes))
    }
}
