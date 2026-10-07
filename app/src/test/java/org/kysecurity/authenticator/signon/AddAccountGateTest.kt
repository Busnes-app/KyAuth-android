package org.kysecurity.authenticator.signon

import android.os.Process
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AddAccountGateTest {
    @Test
    fun allowsSettingsAndPinnedConsumers() {
        assertTrue(mayAddAccount(Process.SYSTEM_UID, trusted = false))
        assertTrue(mayAddAccount(10_123, trusted = true))
    }

    @Test
    fun refusesAnyOtherApp() {
        assertFalse(mayAddAccount(10_123, trusted = false))
        assertFalse(mayAddAccount(-1, trusted = false))
    }
}
