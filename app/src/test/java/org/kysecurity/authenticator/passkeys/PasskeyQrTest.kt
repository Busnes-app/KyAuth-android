package org.kysecurity.authenticator.passkeys

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PasskeyQrTest {
    @Test fun acceptsOnlyBoundedFidoDigitUris() {
        assertEquals("FIDO:/0123456789", PasskeyQr.parse("FIDO:/0123456789"))
        listOf(null, "", "FIDO:/", "FIDO://123", "FIDO:/123?x=1", "FIDO:/123#x",
            "FIDO:/１２３", " FIDO:/123", "FIDO:/123\n", "https://example.com",
            "intent://123#Intent;scheme=FIDO;end", "FIDO:/" + "1".repeat(4091),
        ).forEach { assertNull(it, PasskeyQr.parse(it)) }
    }
}
