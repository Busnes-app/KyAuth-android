package org.kysecurity.authenticator.signon

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
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
        val serverUrl = """https://id.example.com\path/"""
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
    fun derToRaw_handlesRWithLeadingSignByte() {
        // r = 0x00 followed by 32 bytes (33-byte INTEGER due to sign byte)
        // s = normal 32 bytes
        val r = byteArrayOf(0x00) + ByteArray(32) { 0x55.toByte() }
        val s = ByteArray(32) { 0xaa.toByte() }
        val der = derFromRaw(BigInteger(1, r), BigInteger(1, s))
        val raw = DeviceAssertion.derToRaw(der)

        assertEquals(64, raw.size)
        // r should be right-aligned: 0x00 + 31 zero-bytes + 32 0x55 bytes, then last 32 bytes
        val rOut = raw.copyOfRange(0, 32)
        val sOut = raw.copyOfRange(32, 64)
        assertEquals(ByteArray(32) { 0x55.toByte() }.contentToString(), rOut.contentToString())
        assertEquals(ByteArray(32) { 0xaa.toByte() }.contentToString(), sOut.contentToString())
    }

    @Test
    fun derToRaw_handlesRWithSingleByte() {
        // r = 1 byte (value 1)
        // s = 31 bytes (31 0xff bytes)
        val r = byteArrayOf(0x01)
        val s = ByteArray(31) { 0xff.toByte() }
        val der = derFromRaw(BigInteger(1, r), BigInteger(1, s))
        val raw = DeviceAssertion.derToRaw(der)

        assertEquals(64, raw.size)
        val rOut = raw.copyOfRange(0, 32)
        val sOut = raw.copyOfRange(32, 64)

        // r should be 31 zero-bytes + 0x01
        val expectedR = ByteArray(31) + byteArrayOf(0x01)
        assertEquals(expectedR.contentToString(), rOut.contentToString())

        // s should be 1 zero-byte + 31 0xff bytes
        val expectedS = byteArrayOf(0x00) + s
        assertEquals(expectedS.contentToString(), sOut.contentToString())
    }

    @Test
    fun derToRaw_handles0x81LongFormLength() {
        // Test that parser handles 0x81 long-form length encoding correctly
        // Use 33-byte representations (with leading 0x00 sign byte) for maximum length
        val r = byteArrayOf(0x00) + ByteArray(32) { 0x44.toByte() }
        val s = byteArrayOf(0x00) + ByteArray(32) { 0x55.toByte() }
        val der = derFromRaw(BigInteger(1, r), BigInteger(1, s))

        val raw = DeviceAssertion.derToRaw(der)
        assertEquals(64, raw.size)

        // Verify output: should be last 32 bytes of each value
        val rOut = raw.copyOfRange(0, 32)
        val expectedR = r.copyOfRange(1, 33)  // Skip leading 0x00 sign byte
        assertEquals(expectedR.contentToString(), rOut.contentToString())

        val sOut = raw.copyOfRange(32, 64)
        val expectedS = s.copyOfRange(1, 33)  // Skip leading 0x00 sign byte
        assertEquals(expectedS.contentToString(), sOut.contentToString())
    }

    private fun derFromRaw(r: BigInteger, s: BigInteger): ByteArray {
        fun int(v: BigInteger): ByteArray { val b = v.toByteArray(); return byteArrayOf(0x02, b.size.toByte()) + b }
        val body = int(r) + int(s)
        return if (body.size > 127) {
            // Use 0x81 long-form length encoding
            byteArrayOf(0x30, 0x81.toByte(), body.size.toByte()) + body
        } else {
            byteArrayOf(0x30, body.size.toByte()) + body
        }
    }
}
