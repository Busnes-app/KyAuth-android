package org.kysecurity.authenticator.totp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse
import org.junit.Test

class TotpDisplayTest {
    @Test
    fun formatsSixDigitCodesWithoutRebuildingTheScreen() {
        val state = TotpDisplay.state(
            TotpEntry(title = "Example", secretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
            nowEpochSeconds = 0,
            unavailable = "Unavailable",
        )

        assertEquals("755 224", state.formattedCode)
        assertEquals(30, state.remainingSeconds)
        assertFalse(state.requiresReenrolment)
    }

    @Test fun retainedWeakEntryHasNoDisplayOrClipboardCode() {
        val state = TotpDisplay.state(TotpEntry("Legacy", "GE"), 150, "Unavailable")
        assertNull(state.code)
        assertEquals("Unavailable", state.formattedCode)
        assertTrue(state.requiresReenrolment)
    }
}
