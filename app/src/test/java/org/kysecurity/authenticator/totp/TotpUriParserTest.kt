package org.kysecurity.authenticator.totp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Test

class TotpUriParserTest {
    @Test
    fun parsesStandardOtpAuthUri() {
        val uri = "otpauth://totp/KySecurity:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=KySecurity&algorithm=SHA256&digits=8&period=60"
        val entry = TotpUriParser.parse(uri)

        assertEquals("KySecurity (alice@example.com)", entry.title)
        assertEquals("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", entry.secretBase32)
        assertEquals("KySecurity", entry.issuer)
        assertEquals(8, entry.digits)
        assertEquals(60L, entry.periodSeconds)
        assertEquals(TotpEntry.Algorithm.SHA256, entry.algorithm)
    }

    @Test
    fun parsesMinimalOtpAuthUri() {
        val uri = "otpauth://totp/GitHub:user?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY"
        val entry = TotpUriParser.parse(uri)

        assertEquals("GitHub (user)", entry.title)
        assertEquals("GEZDGNBVGY3TQOJQGEZDGNBVGY", entry.secretBase32)
        assertEquals(6, entry.digits)
        assertEquals(30L, entry.periodSeconds)
        assertEquals(TotpEntry.Algorithm.SHA1, entry.algorithm)
    }

    @Test
    fun rejectsInvalidSchemeOrHost() {
        assertThrows(IllegalArgumentException::class.java) {
            TotpUriParser.parse("https://example.com")
        }
        assertThrows(IllegalArgumentException::class.java) {
            TotpUriParser.parse("otpauth://hotp/account?secret=ABC")
        }
    }

    @Test
    fun rejectsSecretThatDecodesToNothing() {
        // A single Base32 character carries five bits and decodes to an empty HMAC key. Accepting
        // it used to persist an entry that crashed the TOTP list on every launch.
        assertThrows(IllegalArgumentException::class.java) {
            TotpUriParser.parse("otpauth://totp/Acme?secret=A")
        }
        assertThrows(IllegalArgumentException::class.java) {
            TotpUriParser.parse("otpauth://totp/Acme?secret=%3D")
        }
    }

    @Test
    fun rejectsImportsBelow128BitsIncludingLegacyExamples() {
        for (secret in listOf("AA", "JBSWY3DPEHPK3PXP", "GEZDGNBVGY3TQOJQGEZDGNBV")) {
            assertThrows(IllegalArgumentException::class.java) {
                TotpUriParser.parse("otpauth://totp/Acme?secret=$secret")
            }
        }
    }
}
