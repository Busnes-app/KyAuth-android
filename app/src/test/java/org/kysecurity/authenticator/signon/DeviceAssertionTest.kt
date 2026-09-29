package org.kysecurity.authenticator.signon

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class DeviceAssertionTest {
    private fun b64url(s: String): ByteArray = Base64.getUrlDecoder().decode(s)

    @Test
    fun signingInput_hasPinnedHeaderAndClaims() {
        val input = DeviceAssertion.signingInput(
            deviceId = "dev-1", userId = "user-1", serverUrl = "https://id.example.com/",
            clientId = "kypost", nowEpochSeconds = 1000, jti = "j-1",
        )
        val (h, c) = input.split(".").let { it[0] to it[1] }
        val header = JSONObject(String(b64url(h)))
        assertEquals(3, header.length())
        assertEquals("ES256", header.getString("alg"))
        assertEquals("JWT", header.getString("typ"))
        assertEquals("dev-1", header.getString("kid"))
        val claims = JSONObject(String(b64url(c)))
        assertEquals("device:dev-1", claims.getString("iss"))
        assertEquals("user-1", claims.getString("sub"))
        assertEquals("https://id.example.com/oauth/token", claims.getString("aud"))
        assertEquals("kypost", claims.getString("client_id"))
        assertEquals(1000L, claims.getLong("iat"))
        assertEquals(1120L, claims.getLong("exp"))
        assertEquals("j-1", claims.getString("jti"))
        assertEquals(7, claims.length())
    }

    @Test
    fun derToRaw_producesSixtyFourBytesThatVerify() {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val input = "a.b".toByteArray()
        val der = Signature.getInstance("SHA256withECDSA").apply { initSign(kp.private); update(input) }.sign()
        val raw = DeviceAssertion.derToRaw(der)
        assertEquals(64, raw.size)
        val r = BigInteger(1, raw.copyOfRange(0, 32))
        val s = BigInteger(1, raw.copyOfRange(32, 64))
        // Re-encode to DER and verify with the JCA to prove r||s carries the same signature.
        val reDer = derFromRaw(r, s)
        val ok = Signature.getInstance("SHA256withECDSA").apply { initVerify(kp.public); update(input) }.verify(reDer)
        assertTrue(ok)
    }

    @Test
    fun compact_isThreeSegmentsUnpaddedBase64Url() {
        val out = DeviceAssertion.compact("h.c", ByteArray(64) { 0xff.toByte() })
        val parts = out.split(".")
        assertEquals(3, parts.size)
        assertFalse(parts[2].contains("="))
        assertFalse(parts[2].contains("+"))
        assertFalse(parts[2].contains("/"))
        assertEquals(64, b64url(parts[2]).size)
    }

    @Test
    fun isValidClientId_boundsCharsetAndLength() {
        assertTrue(DeviceAssertion.isValidClientId("kypost.prod_1:eu-2"))
        assertFalse(DeviceAssertion.isValidClientId(null))
        assertFalse(DeviceAssertion.isValidClientId(""))
        assertFalse(DeviceAssertion.isValidClientId("has space"))
        assertFalse(DeviceAssertion.isValidClientId("x".repeat(129)))
    }

    @Test
    fun signingInput_escapesSpecialCharactersInDeviceIdAndServerUrl() {
        // Test with quotes and backslashes in deviceId and serverUrl
        val deviceId = """dev\"1\"""
        val serverUrl = """https://id.example"test\path/"""
        val input = DeviceAssertion.signingInput(
            deviceId = deviceId, userId = "user-1", serverUrl = serverUrl,
            clientId = "kypost", nowEpochSeconds = 1000, jti = "j-1",
        )
        val (h, c) = input.split(".").let { it[0] to it[1] }

        // Verify header parses correctly and has exactly 3 keys
        val headerObj = JSONObject(String(b64url(h)))
        assertEquals(3, headerObj.length())
        assertEquals("ES256", headerObj.getString("alg"))
        assertEquals("JWT", headerObj.getString("typ"))
        assertEquals(deviceId, headerObj.getString("kid"))

        // Verify claims parse correctly
        val claims = JSONObject(String(b64url(c)))
        assertEquals("device:$deviceId", claims.getString("iss"))
        assertEquals("user-1", claims.getString("sub"))
        val expectedAud = serverUrl.trimEnd('/') + "/oauth/token"
        assertEquals(expectedAud, claims.getString("aud"))
        assertEquals("kypost", claims.getString("client_id"))
    }

    @Test
    fun derToRaw_parsesLiteralDer33ByteR() {
        // Case (a): 33-byte r with sign byte
        // DER: 30 45  02 21 00<32×0xaa>  02 20<32×0x11>
        val der = byteArrayOf(0x30, 0x45,
            0x02, 0x21, 0x00) + ByteArray(32) { 0xaa.toByte() } + byteArrayOf(0x02, 0x20) + ByteArray(32) { 0x11.toByte() }
        val raw = DeviceAssertion.derToRaw(der)

        assertEquals(64, raw.size)
        val expectedRaw = ByteArray(32) { 0xaa.toByte() } + ByteArray(32) { 0x11.toByte() }
        assertEquals(expectedRaw.contentToString(), raw.contentToString())
    }

    @Test
    fun derToRaw_parsesLiteralDerShortIntegers() {
        // Case (b): short integers
        // DER: 30 22  02 01 01  02 1f<31×0x7f>
        val der = byteArrayOf(0x30, 0x22,
            0x02, 0x01, 0x01,
            0x02, 0x1f) + ByteArray(31) { 0x7f.toByte() }
        val raw = DeviceAssertion.derToRaw(der)

        assertEquals(64, raw.size)
        val expectedRaw = ByteArray(31) + byteArrayOf(0x01) + byteArrayOf(0x00) + ByteArray(31) { 0x7f.toByte() }
        assertEquals(expectedRaw.contentToString(), raw.contentToString())
    }

    @Test
    fun derToRaw_parsesLiteralDer0x81LongForm() {
        // Case (c): 0x81 long-form SEQUENCE length
        // DER: 30 81 84  02 40<32×0x00 then 32×0x22>  02 40<32×0x00 then 32×0x33>
        // Body length = 2+64+2+64 = 132 = 0x84
        val der = byteArrayOf(0x30, 0x81.toByte(), 0x84.toByte(),
            0x02, 0x40) + ByteArray(32) { 0x00 } + ByteArray(32) { 0x22.toByte() } +
            byteArrayOf(0x02, 0x40) + ByteArray(32) { 0x00 } + ByteArray(32) { 0x33.toByte() }
        val raw = DeviceAssertion.derToRaw(der)

        assertEquals(64, raw.size)
        val expectedRaw = ByteArray(32) { 0x22.toByte() } + ByteArray(32) { 0x33.toByte() }
        assertEquals(expectedRaw.contentToString(), raw.contentToString())
    }

    @Test
    fun derToRaw_failsOnTruncatedDer() {
        // Truncated DER: 30 09  02 04 00 00 00 00  02 04 00 00 (second INTEGER truncated)
        val der = byteArrayOf(0x30, 0x09, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0x00, 0x00)
        try {
            DeviceAssertion.derToRaw(der)
            fail("Should throw IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            assertTrue("Expected 'bounds' in message: ${e.message}", e.message?.contains("bounds") ?: false)
        }
    }

    @Test
    fun derToRaw_failsOnOversizedInteger() {
        // INTEGER with >256-bit value: 02 21 01<32×0x00> (257-bit value)
        val der = byteArrayOf(0x30, 0x44,
            0x02, 0x21, 0x01) + ByteArray(32) { 0x00 } +
            byteArrayOf(0x02, 0x20) + ByteArray(32) { 0x11.toByte() }
        try {
            DeviceAssertion.derToRaw(der)
            fail("Should throw IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            assertTrue("Expected 'bitLength' in message: ${e.message}", e.message?.contains("bitLength") ?: false)
        }
    }

    private fun derFromRaw(r: BigInteger, s: BigInteger): ByteArray {
        fun int(v: BigInteger): ByteArray { val b = v.toByteArray(); return byteArrayOf(0x02, b.size.toByte()) + b }
        val body = int(r) + int(s)
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}
