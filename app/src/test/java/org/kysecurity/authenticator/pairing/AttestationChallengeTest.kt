package org.kysecurity.authenticator.pairing

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.security.MessageDigest

class AttestationChallengeTest {
    private fun sha(s: String) = MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))

    @Test
    fun tokenPath_usesHashOfPairingToken() {
        val p = QrPairing(serverUrl = "https://id.example", pairingToken = "abc123")
        val cred = "pair1:" + PairingProof.key("abc123").joinToString("") { "%02x".format(it) }
        assertEquals(cred, AttestationChallenge.credential(p))
        assertArrayEquals(sha("kyidentity-attest-v1|$cred"), AttestationChallenge.forPairing(p))
    }

    @Test
    fun pinPath_usesUserIdAndPin() {
        val p = QrPairing(serverUrl = "https://id.example", pinCode = "123456", userId = "u1")
        assertEquals("u1|123456", AttestationChallenge.credential(p))
        assertArrayEquals(sha("kyidentity-attest-v1|u1|123456"), AttestationChallenge.forPairing(p))
    }

    @Test
    fun tokenWinsWhenBothPresent() {
        val p = QrPairing(serverUrl = "https://id.example", pairingToken = "tok", pinCode = "123456", userId = "u1")
        assertEquals(PairingProof.attestationCredential("tok"), AttestationChallenge.credential(p))
    }

    @Test
    fun challengeIsThirtyTwoBytes() {
        assertEquals(32, AttestationChallenge.forPairing(QrPairing(serverUrl = "https://x", pairingToken = "t")).size)
    }
}
