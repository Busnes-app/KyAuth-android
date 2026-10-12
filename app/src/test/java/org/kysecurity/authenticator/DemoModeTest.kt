package org.kysecurity.authenticator

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kysecurity.authenticator.pairing.PairedAccount
import org.kysecurity.authenticator.totp.TotpGenerator
import java.net.URI
import kotlin.random.Random

class DemoModeTest {
    @Test
    fun pairedInstallNeverRunsTheDemo() {
        val paired = PairedAccount("https://id.example.com", "d1", "Pixel")
        assertTrue(DemoMode.active(requested = true, paired = null))
        assertFalse(DemoMode.active(requested = true, paired = paired))
        assertFalse(DemoMode.active(requested = false, paired = null))
    }

    @Test
    fun demoServerCanNeverResolve() {
        assertTrue(URI(DemoMode.account.serverUrl).host.endsWith(".invalid"))
    }

    @Test
    fun demoEntriesGenerateCodes() {
        val entries = DemoMode.entries()
        assertEquals(entries.size, entries.map { it.id }.toSet().size)
        entries.forEach { assertTrue(Regex("\\d{6}").matches(TotpGenerator.generate(it, 1_700_000_000))) }
    }

    @Test
    fun demoChallengeOffersTheMatchAmongThreeDecoys() {
        repeat(200) { seed ->
            val challenge = DemoMode.challenge(nowMs = 1_000, random = Random(seed))
            val options = challenge.options()
            assertEquals(4, options.size)
            assertTrue(challenge.matchDigits in options)
            assertTrue(options.all { Regex("\\d{2}").matches(it) })
            assertEquals(1_000 + DemoMode.PUSH_LIFETIME_MS, challenge.expiresAtEpochMs)
            assertEquals(DemoMode.account.serverUrl, challenge.serverUrl)
        }
    }
}
