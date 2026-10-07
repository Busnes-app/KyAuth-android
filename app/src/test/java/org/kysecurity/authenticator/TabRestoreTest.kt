package org.kysecurity.authenticator

import org.junit.Assert.assertEquals
import org.junit.Test

class TabRestoreTest {
    @Test
    fun removedOrMissingTabsOpenVault() {
        for (old in listOf(null, "", "TOTP", "MFA", "PASSWORDS", "nonsense")) {
            assertEquals("restore($old)", MainActivity.Tab.VAULT, MainActivity.Tab.restore(old))
        }
        assertEquals(MainActivity.Tab.SETTINGS, MainActivity.Tab.restore("SETTINGS"))
    }
}
