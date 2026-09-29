package org.kysecurity.authenticator.signon

import org.json.JSONObject
import java.math.BigInteger
import java.util.Base64

const val ASSERTION_TTL_SECONDS = 120L

/**
 * Builds the RFC 7523 assertion KyIdentity's jwt-bearer grant verifies. Pure: the caller
 * signs [signingInput] with the device key and feeds the DER result through [derToRaw].
 */
object DeviceAssertion {
    private val CLIENT_ID = Regex("[A-Za-z0-9._:-]{1,128}")
    private val b64 = Base64.getUrlEncoder().withoutPadding()

    fun isValidClientId(value: String?): Boolean = value != null && CLIENT_ID.matches(value)

    fun signingInput(
        deviceId: String,
        userId: String,
        serverUrl: String,
        clientId: String,
        nowEpochSeconds: Long,
        jti: String,
    ): String {
        // Manual header construction to ensure key order: alg, typ, kid
        val headerStr = """{"alg":"ES256","typ":"JWT","kid":"$deviceId"}"""
        val claims = JSONObject()
            .put("iss", "device:$deviceId")
            .put("sub", userId)
            .put("aud", serverUrl.trimEnd('/') + "/oauth/token")
            .put("client_id", clientId)
            .put("iat", nowEpochSeconds)
            .put("exp", nowEpochSeconds + ASSERTION_TTL_SECONDS)
            .put("jti", jti)
        return b64.encodeToString(headerStr.toByteArray()) + "." +
            b64.encodeToString(claims.toString().toByteArray())
    }

    /** DER `SEQUENCE { INTEGER r, INTEGER s }` from the JCA to the 64-byte `r||s` JWS expects. */
    fun derToRaw(der: ByteArray): ByteArray {
        require(der.size > 8 && der[0] == 0x30.toByte()) { "Not a DER ECDSA signature" }
        var i = 2
        if (der[1].toInt() and 0x80 != 0) i += der[1].toInt() and 0x7f // long-form length
        fun readInt(): BigInteger {
            require(der[i] == 0x02.toByte()) { "Expected INTEGER" }
            val len = der[i + 1].toInt() and 0xff
            val v = BigInteger(1, der.copyOfRange(i + 2, i + 2 + len))
            i += 2 + len
            return v
        }
        val r = readInt()
        val s = readInt()
        val out = ByteArray(64)
        // Copy r and s as unsigned bytes, right-aligned to 32 bytes each
        copyLeftPadded(r.toByteArray(), out, 0, 32)
        copyLeftPadded(s.toByteArray(), out, 32, 32)
        return out
    }

    fun compact(signingInput: String, rawSignature: ByteArray): String =
        signingInput + "." + b64.encodeToString(rawSignature)

    /** Copy bytes right-aligned (left-padded with zeros) into a 32-byte slot. */
    private fun copyLeftPadded(src: ByteArray, dst: ByteArray, dstOffset: Int, slotSize: Int) {
        val len = minOf(src.size, slotSize)
        val padding = slotSize - len
        src.copyInto(dst, dstOffset + padding, src.size - len, src.size)
    }
}
