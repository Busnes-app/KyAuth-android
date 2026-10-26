package org.kysecurity.authenticator.totp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class TotpGeneratorTest {
    @Test fun `matches RFC 6238 SHA-1 vector`() {
        val entry = TotpEntry("RFC", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", digits = 8)
        assertEquals("94287082", TotpGenerator.generate(entry, 59))
    }

    @Test fun `refuses undersized legacy secrets for every supported HMAC`() {
        for (algorithm in TotpEntry.Algorithm.entries) {
            for (secret in listOf("GE", "GEZDGNBVGY3TQOJQGEZDG", "GEZDGNBVGY3TQOJQGEZDGNBV")) {
                val entry = TotpEntry("Retained account", secret, algorithm = algorithm)
                assertThrows(IllegalArgumentException::class.java) { TotpGenerator.generate(entry, 150) }
                assertEquals(secret, entry.secretBase32)
            }
        }
    }

    @Test fun `accepts RFC 4226 minimum length with independent counter five value`() {
        val entry = TotpEntry("Minimum", "GEZDGNBVGY3TQOJQGEZDGNBVGY") // first 16 RFC test-key bytes
        assertEquals("715195", TotpGenerator.generate(entry, 150))
    }
}
