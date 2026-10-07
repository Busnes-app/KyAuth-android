package org.kysecurity.authenticator.mfa

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class MfaMessageTest {
    private fun msg(purpose: String, approve: Boolean, digits: String) = String(
        MfaMessage.formatPayload("https://id.example.com", "u-123", "d-456", "c-789", purpose, 1791331200000, approve, digits),
        Charsets.UTF_8,
    )

    @Test fun goldenVectors() {
        assertEquals("kyidentity-push-v2|https://id.example.com|u-123|d-456|c-789|login|1791331200000|approve|42", msg("login", true, "42"))
        assertEquals("kyidentity-push-v2|https://id.example.com|u-123|d-456|c-789|step_up|1791331200000|deny|", msg("step_up", false, ""))
    }

    @Test fun refusesAmbiguousFields() {
        assertThrows(IllegalArgumentException::class.java) { msg("session", true, "42") }
        assertThrows(IllegalArgumentException::class.java) {
            MfaMessage.formatPayload("https://id.example.com", "u|1", "d", "c", "login", 1, true, "42")
        }
        assertThrows(IllegalArgumentException::class.java) {
            MfaMessage.formatPayload("https://id.example.com", "", "d", "c", "login", 1, true, "42")
        }
    }

    @Test fun originVectors() {
        assertEquals("https://id.example.com", MfaMessage.origin("https://ID.Example.com/"))
        assertEquals("https://id.example.com", MfaMessage.origin("https://id.example.com:443"))
        assertEquals("https://id.example.com:8443", MfaMessage.origin("https://id.example.com:8443/kyidentity"))
        assertEquals("http://127.0.0.1:8080", MfaMessage.origin("http://127.0.0.1:8080"))
        assertEquals("https://[::1]", MfaMessage.origin("https://[::1]"))
        assertEquals("https://[::1]:8443", MfaMessage.origin("https://[::1]:8443/x"))
        assertThrows(IllegalArgumentException::class.java) { MfaMessage.origin("not a url") }
    }

    @Test
    fun challengeOptionsIncludeMatchAndDecoysSorted() {
        val challenge = MfaChallenge(
            challengeId = "ch-1",
            matchDigits = "42",
            decoyDigits = listOf("88", "12", "55"),
            serverUrl = "https://auth.example.com",
            purpose = "login",
            expiresAtEpochMs = 1L,
        )
        assertEquals(listOf("12", "42", "55", "88"), challenge.options())
    }
}
