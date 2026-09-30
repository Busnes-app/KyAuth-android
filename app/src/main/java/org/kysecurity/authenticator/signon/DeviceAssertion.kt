package org.kysecurity.authenticator.signon

import org.json.JSONObject
import java.math.BigInteger
import java.net.URI
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

    /** The relay the consumer typed, as `https://host[:port]`; null unless it is plain HTTPS. */
    fun relayOrigin(raw: String?): String? {
        val uri = runCatching { URI(raw) }.getOrNull() ?: return null
        if (!uri.scheme.equals("https", ignoreCase = true) || uri.rawUserInfo != null) return null
        val host = uri.host?.lowercase()?.takeIf { it.isNotEmpty() } ?: return null
        return if (uri.port == -1 || uri.port == 443) "https://$host" else "https://$host:${uri.port}"
    }

    fun signingInput(
        deviceId: String,
        userId: String,
        serverUrl: String,
        clientId: String,
        origin: String,
        nowEpochSeconds: Long,
        jti: String,
    ): String {
        val header = JSONObject().put("alg", "ES256").put("typ", "JWT").put("kid", deviceId)
        val claims = JSONObject()
            .put("iss", "device:$deviceId")
            .put("sub", userId)
            .put("aud", serverUrl.trimEnd('/') + "/oauth/token")
            .put("client_id", clientId)
            .put("iat", nowEpochSeconds)
            .put("exp", nowEpochSeconds + ASSERTION_TTL_SECONDS)
            .put("jti", jti)
            .put("origin", origin)
        return b64.encodeToString(header.toString().toByteArray()) + "." +
            b64.encodeToString(claims.toString().toByteArray())
    }

    /** DER `SEQUENCE { INTEGER r, INTEGER s }` from the JCA to the 64-byte `r||s` JWS expects. */
    fun derToRaw(der: ByteArray): ByteArray {
        require(der.size > 8 && der[0] == 0x30.toByte()) { "Not a DER ECDSA signature" }
        var i = 2
        if (der[1].toInt() and 0x80 != 0) i += der[1].toInt() and 0x7f // long-form length
        fun readInt(): BigInteger {
            require(i + 1 < der.size) { "DER bounds violation: can't read tag/length at offset $i" }
            require(der[i] == 0x02.toByte()) { "Expected INTEGER" }
            val len = der[i + 1].toInt() and 0xff
            require(i + 2 + len <= der.size) { "DER bounds violation: INTEGER value extends past end at offset $i, length $len" }
            val v = BigInteger(1, der.copyOfRange(i + 2, i + 2 + len))
            i += 2 + len
            return v
        }
        val r = readInt()
        val s = readInt()
        require(r.bitLength() <= 256) { "r bitLength exceeds 256 bits" }
        require(s.bitLength() <= 256) { "s bitLength exceeds 256 bits" }
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
        // For BigInteger.toByteArray(), take only the last slotSize bytes (handles leading sign byte)
        val len = minOf(src.size, slotSize)
        val padding = slotSize - len
        val startIdx = src.size - len
        src.copyInto(dst, dstOffset + padding, startIdx, src.size)
    }
}
