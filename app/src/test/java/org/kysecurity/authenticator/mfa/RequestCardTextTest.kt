package org.kysecurity.authenticator.mfa

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

class RequestCardTextTest {
    private fun challenge(serverUrl: String = "https://auth.example", username: String? = null) = MfaChallenge(
        challengeId = "c1", decoyDigits = emptyList(), serverUrl = serverUrl, username = username,
        purpose = "login", expiresAtEpochMs = 0,
    )

    @Test
    fun countsDownInMinutesAndSeconds() {
        mapOf(
            300L to "Expires in 5:00", 299L to "Expires in 4:59", 61L to "Expires in 1:01", 60L to "Expires in 1:00",
            59L to "Expires in 0:59", 9L to "Expires in 0:09", 1L to "Expires in 0:01", 600L to "Expires in 10:00",
        ).forEach { (seconds, text) -> assertEquals(text, RequestCardText.expiry(seconds)) }
    }

    @Test
    fun readsExpiredAtZero() {
        assertEquals("Expired", RequestCardText.expiry(0))
        assertEquals("Expired", RequestCardText.expiry(-3))
    }

    @Test
    fun showsTheServerAsHostOnly() {
        mapOf(
            "https://auth.example" to "auth.example",
            "https://auth.example/" to "auth.example",
            " https://Auth.Example:443/idp?x=1 " to "auth.example",
            "https://auth.example:8443" to "auth.example:8443",
            "http://127.0.0.1:8080" to "127.0.0.1:8080",
            "not a url" to "not a url",
        ).forEach { (url, host) -> assertEquals(url, host, RequestCardText.server(url)) }
    }

    @Test
    fun namesThePushedAccountFirstThenThePairedOne() {
        assertEquals("alice", RequestCardText.account(challenge(username = "alice"), "paired-name"))
        assertEquals("paired-name", RequestCardText.account(challenge(), "paired-name"))
        assertEquals("paired-name", RequestCardText.account(challenge(username = " "), " paired-name "))
        assertNull(RequestCardText.account(challenge(), null))
        assertNull(RequestCardText.account(challenge(), ""))
    }

    @Test
    fun detailsNameAccountAndServer() {
        assertEquals("Account: alice\nServer: auth.example", RequestCardText.details(challenge(username = "alice"), null))
    }

    // A legacy push from a pairing that saved no username: no account line, never the phone's name.
    @Test
    fun detailsWithoutAnyUsernameShowOnlyTheServer() {
        val details = RequestCardText.details(challenge(), null)
        assertEquals("Server: auth.example", details)
        assertFalse(details.contains("User"))
    }
}
