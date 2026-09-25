package org.kysecurity.authenticator.passkeys

/** URI framing only; Play services validates the encoded CBOR and session. */
object PasskeyQr {
    fun parse(value: String?): String? {
        if (value == null || value.length !in 7..4096 || !value.startsWith("FIDO:/")) return null
        return value.takeIf { it.substring(6).all { digit -> digit in '0'..'9' } }
    }
}
