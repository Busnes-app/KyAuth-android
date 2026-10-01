package org.kysecurity.authenticator.pairing

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.security.MessageDigest

class AttestationChallengeTest {
    private fun sha(s: String) = MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))

    @Test
    fun tokenPath_usesPairingToken() {
        val p = QrPairing(serverUrl = "https://id.example", pairingToken = "abc123")
        assertEquals("abc123", AttestationChallenge.credential(p))
        assertArrayEquals(sha("kyidentity-attest-v1|abc123"), AttestationChallenge.forPairing(p))
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
        assertEquals("tok", AttestationChallenge.credential(p))
    }

    @Test
    fun challengeIsThirtyTwoBytes() {
        assertEquals(32, AttestationChallenge.forPairing(QrPairing(serverUrl = "https://x", pairingToken = "t")).size)
    }
}
