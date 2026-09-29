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
        assertEquals("""{"alg":"ES256","typ":"JWT","kid":"dev-1"}""", String(b64url(h)))
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

    private fun derFromRaw(r: BigInteger, s: BigInteger): ByteArray {
        fun int(v: BigInteger): ByteArray { val b = v.toByteArray(); return byteArrayOf(0x02, b.size.toByte()) + b }
        val body = int(r) + int(s)
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}
