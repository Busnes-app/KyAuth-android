package org.kysecurity.authenticator.mfa

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.kysecurity.authenticator.pairing.PairedAccount

class IncomingPushTest {
    private val account = PairedAccount("https://id.example.com", "d-456", "Pixel", "alice", "u-123")
    private val now = 1_000_000L
    private val valid = mapOf(
        "type" to "mfa_challenge",
        "title" to "Sign-in request",
        "body" to "Approve?",
        "challengeId" to "ch-1",
        "deviceId" to "d-456",
        "deviceUserId" to "u-123",
        "purpose" to "login",
        "expiresAtEpochMs" to (now + 60_000).toString(),
        "devicePlatform" to "android",
    )

    // Every transport must reach the same parser: FCM hands a map, UnifiedPush a JSON body.
    private val transports: List<(Map<String, String>) -> Map<String, String>?> = listOf(
        { it },
        { IncomingPush.unifiedPushData(JSONObject(it).toString().toByteArray()) },
    )

    private fun accepted(data: Map<String, String>) = transports.map { decode ->
        decode(data)?.let { IncomingPush.challenge(it, account, now) }
    }

    @Test
    fun acceptsValidChallengeOnEveryTransport() {
        accepted(valid).forEach { assertEquals("ch-1", it?.challengeId) }
    }

    @Test
    fun refusesOtherDeviceUserOrExpiredOnEveryTransport() {
        listOf(
            valid + ("deviceId" to "d-other"),
            valid + ("deviceUserId" to "u-other"),
            valid + ("expiresAtEpochMs" to (now - 1).toString()),
        ).forEach { data -> accepted(data).forEach { assertNull(it) } }
    }

    @Test
    fun refusesUnifiedPushBodyThatIsNotAFlatStringObject() {
        assertNull(IncomingPush.unifiedPushData("""{"challengeId":1}""".toByteArray()))
        assertNull(IncomingPush.unifiedPushData("""{"a":{"b":"c"}}""".toByteArray()))
        assertNull(IncomingPush.unifiedPushData("not json".toByteArray()))
    }
}
