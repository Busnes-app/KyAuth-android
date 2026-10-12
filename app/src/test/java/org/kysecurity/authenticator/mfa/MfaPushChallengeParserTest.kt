package org.kysecurity.authenticator.mfa

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kysecurity.authenticator.pairing.PairedAccount

class MfaPushChallengeParserTest {
    private val paired = "https://id.example.com"
    private val account = PairedAccount(paired, "d-456", "Pixel", "alice", "u-123", canSignOn = false)
    private val now = 1_000_000L

    private fun data(vararg extra: Pair<String, String>, drop: String? = null): Map<String, String> =
        (mapOf(
            "challengeId" to "ch-1",
            "matchDigits" to "42",
            "deviceId" to "d-456",
            "deviceUserId" to "u-123",
            "purpose" to "login",
            "expiresAtEpochMs" to (now + 60_000).toString(),
        ) + extra).filterKeys { it != drop }

    private fun parse(d: Map<String, String>, p: PairedAccount? = account) =
        MfaPushChallengeParser.parse(d, p, now)

    private fun refused(d: Map<String, String>, p: PairedAccount? = account) {
        assertThrows(IllegalArgumentException::class.java) { parse(d, p) }
    }

    @Test
    fun parsesKyIdentityPushChallengeDataPayload() {
        val challenge = parse(data("decoyDigits" to """["12","55","88"]""", "username" to "alice"))

        assertEquals("ch-1", challenge.challengeId)
        assertEquals("42", challenge.matchDigits)
        assertEquals(listOf("12", "55", "88"), challenge.decoyDigits)
        assertEquals(paired, challenge.serverUrl)
        assertEquals("alice", challenge.username)
        assertEquals("login", challenge.purpose)
        assertEquals(now + 60_000, challenge.expiresAtEpochMs)
    }

    @Test
    fun acceptsStepUpAndRelayAliases() {
        val challenge = parse(
            mapOf(
                "id" to "ch-456", "match" to "19", "decoys" to "22,33,44",
                "deviceId" to "d-456", "deviceUserId" to "u-123", "purpose" to "step_up",
                "expiresAtEpochMs" to (now + 1_000).toString(),
            ),
        )

        assertEquals("ch-456", challenge.challengeId)
        assertEquals("19", challenge.matchDigits)
        assertEquals(listOf("22", "33", "44"), challenge.decoyDigits)
        assertEquals("step_up", challenge.purpose)
    }

    @Test
    fun ignoresAServerUrlSuppliedByThePushPayload() {
        val challenge = parse(data("serverUrl" to "https://attacker.example", "server_url" to "https://attacker.example"))
        assertEquals(paired, challenge.serverUrl)
    }

    @Test fun refusesWithoutAPairing() = refused(data(), null)

    @Test fun refusesAPairingWithoutUserId() = refused(data(), account.copy(userId = null))

    @Test fun refusesAPushForAnotherDevice() = refused(data("deviceId" to "d-999"))

    @Test fun refusesAPushForAnotherAccount() = refused(data("deviceUserId" to "u-999"))

    @Test fun refusesMissingBinding() {
        refused(data(drop = "deviceId"))
        refused(data(drop = "deviceUserId"))
    }

    @Test fun refusesMissingOrUnknownPurpose() {
        refused(data(drop = "purpose"))
        refused(data("purpose" to "session"))
    }

    @Test fun refusesMissingExpiry() = refused(data(drop = "expiresAtEpochMs"))

    @Test fun refusesExpiryElevenMinutesOutInsteadOfClamping() =
        refused(data("expiresAtEpochMs" to (now + 11 * 60_000).toString()))

    @Test
    fun acceptsExpiryAtTheTenMinuteLimit() {
        val at = now + MfaPushChallengeParser.MAX_EXPIRES_AFTER_MS
        assertEquals(at, parse(data("expiresAtEpochMs" to at.toString())).expiresAtEpochMs)
    }

    @Test fun refusesExpiryInThePast() = refused(data("expiresAtEpochMs" to "500"))

    @Test
    fun noLongerAcceptsTheSecondsExpiryAlias() =
        refused(data("expiresAt" to ((now + 60_000) / 1_000).toString(), drop = "expiresAtEpochMs"))

    @Test
    fun rejectsMalformedMatchDigits() {
        assertThrows(IllegalArgumentException::class.java) {
            parse(data("matchDigits" to "42x"))
        }
    }

    @Test
    fun dropsMalformedDuplicateAndExcessDecoys() {
        val challenge = parse(data("decoyDigits" to "11,11,notdigits,42,22,33,44,55"))

        assertEquals(listOf("11", "22", "33"), challenge.decoyDigits)
        assertTrue(challenge.decoyDigits.size <= MfaPushChallengeParser.MAX_DECOYS)
    }
}
