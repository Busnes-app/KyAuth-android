package org.kysecurity.authenticator.pairing

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/** Golden vector from the pairing proof v1 spec; KyIdentity pins the same values. */
class PairingProofTest {
    private val token = "00112233445566778899aabbccddeeff0011223344556677"
    private val origin = "https://id.example.com"
    private val request =
        """{"userId":"user-1","deviceName":"Pixel","deviceIdentifier":"inst-1","platform":"android","publicKey":"BAAA","pushToken":"tok","pushTransport":"fcm"}"""
            .toByteArray()
    private val response = "{\"success\":true,\"deviceId\":\"dev-1\",\"device\":{\"id\":\"dev-1\"}}\n".toByteArray()
    private val requestProof = "mJoloQsGw4y-mlo2Lo3pMsesJrVna3FPQN4DuV5HaTs"
    private val replyProof = "QsV0h3Srdjg805wx19o-D3Ee1KhzmKAz1RqP4Zu0Q-Y"
    private val pairing = QrPairing(serverUrl = "https://ID.example.com:443/", pairingToken = token, userId = "user-1")

    private fun reply(body: ByteArray = response, vararg proof: String) =
        ServerHttp.Response(200, body, if (proof.isEmpty()) emptyMap() else mapOf("kyidentity-pairing-proof" to proof.toList()))

    private fun accept(r: ServerHttp.Response) = PairingClient().accept(pairing, request, r, "Pixel")

    @Test
    fun goldenVector() {
        val key = PairingProof.key(token)
        assertEquals("8f7bb6e4f056bb6d1846aa7544964867c93afdd56ec29c73c46aac8ebd8f8d76", key.joinToString("") { "%02x".format(it) })
        assertEquals(requestProof, PairingProof.requestProof(key, origin, request))
        assertEquals("cykwj-49G__TJq22JeLvRDBE4qzm3_BRgfznUMMoiag", PairingProof.requestHash(request))
        assertEquals(replyProof, PairingProof.replyProof(key, origin, request, response))
        assertEquals("pair1:8f7bb6e4f056bb6d1846aa7544964867c93afdd56ec29c73c46aac8ebd8f8d76", AttestationChallenge.credential(pairing))
        assertEquals(
            "d15e7280b1406114c113bd5019d7b8a11f06f575938872fa2bb82a450208e4e7",
            AttestationChallenge.forPairing(pairing).joinToString("") { "%02x".format(it) },
        )
    }

    @Test
    fun keyIsNotTheStoredTokenHash() {
        val tokenHash = MessageDigest.getInstance("SHA-256").digest(token.toByteArray())
        assertFalse(PairingProof.key(token).contentEquals(tokenHash))
    }

    @Test
    fun requestHeaderUsesTheCanonicalOriginOfTheQrServer() {
        assertEquals(mapOf(PairingProof.HEADER to requestProof), PairingClient().proofHeaders(pairing, request))
    }

    @Test
    fun tokenRequestBodyCarriesUserIdAndNoSecret() {
        val body = JSONObject(
            PairingClient().registrationRequestJson(
                QrPairing(serverUrl = origin, pairingToken = token, pinCode = "123456", userId = "user-1"),
                "Pixel", "inst-1", PushCredential(PushCredential.FCM, "tok"), "BAAA",
            ),
        )
        assertFalse(body.has("pairingToken"))
        assertFalse(body.has("pinCode"))
        assertEquals("user-1", body.getString("userId"))
    }

    @Test
    fun tokenPairingWithoutUserIdIsRefusedBeforeSending() {
        val e = assertThrows(IllegalArgumentException::class.java) {
            PairingClient().proofHeaders(QrPairing(serverUrl = origin, pairingToken = token), request)
        }
        assertEquals(NEEDS_USER_ID, e.message)
    }

    @Test
    fun verifiedReplyIsAccepted() {
        assertEquals("dev-1", accept(reply(response, replyProof)).deviceId)
    }

    @Test
    fun tamperedReplyIsRefused() {
        val forged = "{\"success\":true,\"deviceId\":\"dev-2\",\"device\":{\"id\":\"dev-2\"}}\n".toByteArray()
        val trailing = response.copyOf(response.size - 1) // the same JSON without Go's newline
        for (r in listOf(reply(forged, replyProof), reply(trailing, replyProof), reply(response, requestProof))) {
            assertEquals(REPLY_UNVERIFIED, assertThrows(IllegalStateException::class.java) { accept(r) }.message)
        }
    }

    @Test
    fun missingOrRepeatedReplyHeaderIsRefused() {
        for (r in listOf(reply(response), reply(response, replyProof, replyProof))) {
            assertEquals(REPLY_UNVERIFIED, assertThrows(IllegalStateException::class.java) { accept(r) }.message)
        }
    }

    @Test
    fun replyCheckIsByExactBytes() {
        val key = PairingProof.key(token)
        assertTrue(PairingProof.replyVerified(key, origin, request, response, replyProof))
        assertFalse(PairingProof.replyVerified(key, origin, request + ' '.code.toByte(), response, replyProof))
        assertFalse(PairingProof.replyVerified(key, "https://id.example.com:8443", request, response, replyProof))
        assertFalse(PairingProof.replyVerified(key, origin, request, response, null))
    }

    @Test
    fun errorReplyNeedsNoProof() {
        val e = assertThrows(IllegalStateException::class.java) {
            accept(ServerHttp.Response(400, """{"error":"registration_failed"}"""))
        }
        assertEquals("registration_failed", e.message)
    }

    @Test
    fun pinPairingIsUnchanged() {
        val pin = QrPairing(serverUrl = origin, pinCode = "123456", userId = "user-1")
        val body = JSONObject(PairingClient().registrationRequestJson(pin, "Pixel", "inst-1", null, "BAAA"))
        assertEquals(setOf("pinCode", "userId", "deviceName", "deviceIdentifier", "platform", "publicKey"), body.keys().asSequence().toSet())
        assertEquals("123456", body.getString("pinCode"))
        assertEquals(emptyMap<String, String>(), PairingClient().proofHeaders(pin, request))
        assertEquals("user-1|123456", AttestationChallenge.credential(pin))
        // No reply header is expected on the PIN path.
        assertEquals("dev-1", PairingClient().accept(pin, request, reply(response), "Pixel").deviceId)
    }
}
