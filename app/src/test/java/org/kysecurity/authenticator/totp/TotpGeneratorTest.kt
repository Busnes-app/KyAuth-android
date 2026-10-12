package org.kysecurity.authenticator.totp

import org.junit.Assert.assertEquals
import org.junit.Test

class TotpGeneratorTest {
    @Test fun `matches RFC 6238 SHA-1 vector`() {
        val entry = TotpEntry("RFC", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", digits = 8)
        assertEquals("94287082", TotpGenerator.generate(entry, 59))
    }
}
