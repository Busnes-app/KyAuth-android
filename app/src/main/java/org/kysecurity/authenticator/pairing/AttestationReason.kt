package org.kysecurity.authenticator.pairing

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

/** Why a pairing ended up ungraded, so Settings can say whether pairing again can help. */
object AttestationReason {
    const val NONE = ""
    const val SERVER_UNSUPPORTED = "server-unsupported"
    const val KEYSTORE_SOFTWARE = "keystore-software"
    const val NOT_ACCEPTED = "not-accepted"

    private const val KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"

    fun classify(level: String, serverReportedLevel: Boolean, chain: List<String>): String =
        classify(level, serverReportedLevel, chain, ::leafSecurityLevel)

    internal fun classify(
        level: String,
        serverReportedLevel: Boolean,
        chain: List<String>,
        leafLevel: (String) -> Int?,
    ): String = when {
        level != "none" -> NONE
        !serverReportedLevel -> SERVER_UNSUPPORTED
        chain.isEmpty() -> KEYSTORE_SOFTWARE
        leafLevel(chain[0]).let { it != 1 && it != 2 } -> KEYSTORE_SOFTWARE
        else -> NOT_ACCEPTED
    }

    /** attestationSecurityLevel from the leaf's KeyDescription, or null when absent/unparseable. */
    fun leafSecurityLevel(leafDerBase64: String): Int? = runCatching {
        val cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(Base64.getDecoder().decode(leafDerBase64))) as X509Certificate
        cert.getExtensionValue(KEY_DESCRIPTION_OID)?.let(::leafSecurityLevel)
    }.getOrNull()

    /** Reads SEQUENCE { INTEGER version, ENUMERATED securityLevel, ... } inside the extension's OCTET STRING. */
    internal fun leafSecurityLevel(extensionValue: ByteArray): Int? {
        val octet = tlv(extensionValue, 0, 0x04) ?: return null
        val seq = tlv(extensionValue, octet.first, 0x30) ?: return null
        val version = tlv(extensionValue, seq.first, 0x02) ?: return null
        val level = tlv(extensionValue, version.second, 0x0A) ?: return null
        return if (level.second - level.first == 1) extensionValue[level.first].toInt() and 0xFF else null
    }

    /** Checks the tag at [pos]; returns (content start, content end) or null. */
    private fun tlv(b: ByteArray, pos: Int, tag: Int): Pair<Int, Int>? {
        if (pos + 2 > b.size || (b[pos].toInt() and 0xFF) != tag) return null
        val first = b[pos + 1].toInt() and 0xFF
        var start = pos + 2
        var len = first
        if (first >= 0x80) {
            val n = first and 0x7F
            if (n == 0 || n > 3 || start + n > b.size) return null
            len = 0
            repeat(n) { len = (len shl 8) or (b[start++].toInt() and 0xFF) }
        }
        val end = start + len
        return if (end > b.size) null else start to end
    }
}
