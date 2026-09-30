package org.kysecurity.authenticator.signon

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.kysecurity.authenticator.pairing.PairedAccount

class PendingSignOnTest {
    private var now = 1_000L
    private val req = SignOnRequest.Proceed(
        TrustedCaller("org.kysecurity.mail", "KyPost"), "kypost", "https://mail.example.com",
        PairedAccount("https://id.example.com", "d", "P", "alice", "u1", canSignOn = true),
    )

    init { PendingSignOn.clock = { now } }

    @After
    fun reset() { PendingSignOn.clock = System::currentTimeMillis }

    @Test
    fun roundTrip_thenSecondTakeIsNull() {
        val n = PendingSignOn.issue(req)
        assertEquals(req, PendingSignOn.take(n))
        assertNull(PendingSignOn.take(n))
    }

    @Test
    fun unknownAndNullAreNull() {
        assertNull(PendingSignOn.take("nope"))
        assertNull(PendingSignOn.take(null))
    }

    @Test
    fun expiredIsNull() {
        val n = PendingSignOn.issue(req)
        now += 120_000L
        assertNull(PendingSignOn.take(n))
    }

    @Test
    fun noncesDiffer() {
        assertNotEquals(PendingSignOn.issue(req), PendingSignOn.issue(req))
    }
}
