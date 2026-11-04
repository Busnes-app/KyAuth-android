package org.kysecurity.authenticator.totp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

class TotpGeneratorTest {
    @Test fun `matches RFC 6238 SHA-1 vector`() {
        val entry = TotpEntry("RFC", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", digits = 8)
        assertEquals("94287082", TotpGenerator.generate(entry, 59))
    }

    @Test fun `refuses undersized legacy secrets for every supported HMAC`() {
        for (algorithm in TotpEntry.Algorithm.entries) {
            for (secret in listOf("GE", "GEZDGNBVGY3TQOJ")) { // 0 and 9 bytes: below the 80-bit floor
                val entry = TotpEntry("Retained account", secret, algorithm = algorithm)
                assertThrows(IllegalArgumentException::class.java) { TotpGenerator.generate(entry, 150) }
                assertEquals(secret, entry.secretBase32)
            }
        }
    }

    @Test fun `accepts an issuer's 80-bit key and marks it short`() {
        val entry = TotpEntry("GitHub", "GEZDGNBVGY3TQOJQ") // first 10 RFC test-key bytes
        assertEquals("767654", TotpGenerator.generate(entry, 150))
        TotpGenerator.requireStrongSecret("JBSWY3DPEHPK3PXP")
        assertTrue(TotpGenerator.isShortSecret(entry.secretBase32))
        assertFalse(TotpGenerator.isShortSecret("GEZDGNBVGY3TQOJQGEZDGNBVGY"))
    }

    @Test fun `accepts RFC 4226 minimum length with independent counter five value`() {
        val entry = TotpEntry("Minimum", "GEZDGNBVGY3TQOJQGEZDGNBVGY") // first 16 RFC test-key bytes
        assertEquals("715195", TotpGenerator.generate(entry, 150))
    }
}
