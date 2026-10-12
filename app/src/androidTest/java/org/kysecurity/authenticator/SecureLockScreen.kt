package org.kysecurity.authenticator

import android.app.KeyguardManager
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.rules.ExternalResource

/**
 * Gives the Keystore tests the secure lock screen they need, only for as long as they run.
 * CI sets no PIN up front: a PIN keyguard on the emulator can re-appear at any moment and
 * briefly stop the UI tests' activity, which locks the app. A device that already has a
 * credential (a developer's own) is left alone.
 */
class SecureLockScreen : ExternalResource() {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val keyguard = instrumentation.targetContext.getSystemService(KeyguardManager::class.java)
    private var setHere = false

    override fun before() {
        if (keyguard.isDeviceSecure) return
        shell("locksettings set-pin $PIN")
        setHere = true
        val deadline = SystemClock.elapsedRealtime() + 5_000
        while (!keyguard.isDeviceSecure) {
            check(SystemClock.elapsedRealtime() < deadline) { "Could not set a test lock screen PIN" }
            SystemClock.sleep(100)
        }
    }

    override fun after() {
        if (setHere) shell("locksettings clear --old $PIN")
    }

    private fun shell(command: String) {
        ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command)).use { it.readBytes() }
    }

    private companion object {
        const val PIN = "246810"
    }
}
