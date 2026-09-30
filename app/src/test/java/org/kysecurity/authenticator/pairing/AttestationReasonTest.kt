package org.kysecurity.authenticator.pairing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AttestationReasonTest {
    private fun der(tag: Int, content: ByteArray): ByteArray {
        val len = content.size
        val header = when {
            len < 0x80 -> byteArrayOf(tag.toByte(), len.toByte())
            len < 0x100 -> byteArrayOf(tag.toByte(), 0x81.toByte(), len.toByte())
            else -> byteArrayOf(tag.toByte(), 0x82.toByte(), (len shr 8).toByte(), len.toByte())
        }
        return header + content
    }

    /** OCTET STRING { SEQUENCE { INTEGER 300, ENUMERATED level, [padding] OCTET STRING } }. */
    private fun extension(level: Int, padding: Int = 0): ByteArray {
        val seq = der(0x02, byteArrayOf(0x01, 0x2C)) + der(0x0A, byteArrayOf(level.toByte())) + der(0x04, ByteArray(padding))
        return der(0x04, der(0x30, seq))
    }

    @Test
    fun leafSecurityLevel_readsEachLevel() {
        for (level in 0..2) assertEquals(level, AttestationReason.leafSecurityLevel(extension(level)))
    }

    @Test
    fun leafSecurityLevel_readsLongFormLengths() {
        assertEquals(2, AttestationReason.leafSecurityLevel(extension(2, padding = 200)))
        assertEquals(1, AttestationReason.leafSecurityLevel(extension(1, padding = 600)))
    }

    @Test
    fun leafSecurityLevel_garbageIsNull() {
        assertNull(AttestationReason.leafSecurityLevel(ByteArray(0)))
        assertNull(AttestationReason.leafSecurityLevel(byteArrayOf(0x04, 0x05, 0x30)))
        assertNull(AttestationReason.leafSecurityLevel(byteArrayOf(0x01, 0x02, 0x03, 0x04)))
        assertNull(AttestationReason.leafSecurityLevel(extension(1).copyOf(6)))
        assertNull(AttestationReason.leafSecurityLevel(der(0x04, der(0x30, der(0x02, byteArrayOf(1)) + der(0x02, byteArrayOf(1))))))
        assertNull(AttestationReason.leafSecurityLevel(byteArrayOf(0x04, 0x04, 0x30, 0x80.toByte(), 0x00, 0x00)))
        assertNull(AttestationReason.leafSecurityLevel(byteArrayOf(0x04, 0x03, 0x30, 0x20, 0x02)))
        assertNull(AttestationReason.leafSecurityLevel(der(0x04, der(0x30, der(0x02, byteArrayOf(1)) + der(0x0A, ByteArray(0))))))
        assertNull(AttestationReason.leafSecurityLevel("not base64!"))
        assertNull(AttestationReason.leafSecurityLevel("AAAA"))
    }

    @Test
    fun classify_coversEveryBranch() {
        assertEquals("", AttestationReason.classify("tee", true, emptyList()))
        assertEquals("", AttestationReason.classify("strongbox", false, emptyList()))
        assertEquals(AttestationReason.SERVER_UNSUPPORTED, AttestationReason.classify("none", false, listOf("x")))
        assertEquals(AttestationReason.KEYSTORE_SOFTWARE, AttestationReason.classify("none", true, emptyList()))
        assertEquals(AttestationReason.KEYSTORE_SOFTWARE, AttestationReason.classify("none", true, listOf("AAAA")))
    }

    @Test
    fun classify_hardwareLeafTheServerRefusedIsNotAccepted() {
        for (level in listOf(1, 2)) assertEquals(AttestationReason.NOT_ACCEPTED, AttestationReason.classify("none", true, listOf("leaf"), { level }))
        assertEquals(AttestationReason.KEYSTORE_SOFTWARE, AttestationReason.classify("none", true, listOf("leaf"), { 0 }))
        assertEquals(AttestationReason.KEYSTORE_SOFTWARE, AttestationReason.classify("none", true, listOf("leaf"), { null }))
    }
}
