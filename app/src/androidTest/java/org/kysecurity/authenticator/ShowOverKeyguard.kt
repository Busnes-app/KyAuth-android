package org.kysecurity.authenticator

import android.app.Activity
import android.app.Application
import android.app.KeyguardManager
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.rules.ExternalResource

/**
 * Test-only: shows [MainActivity] above the keyguard, so a keyguard on the test device cannot
 * stop the activity and trip the lock-on-stop behaviour these tests assert on. The app itself
 * never shows over the lock screen. CI also sets no PIN while these run (see [SecureLockScreen]).
 */
class ShowOverKeyguard : ExternalResource() {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val app = instrumentation.targetContext.applicationContext as Application

    private val callbacks = object : Application.ActivityLifecycleCallbacks {
        override fun onActivityPreCreated(activity: Activity, savedInstanceState: Bundle?) {
            if (activity is MainActivity) {
                activity.setShowWhenLocked(true)
                activity.setTurnScreenOn(true)
            }
        }
        override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = Unit
        override fun onActivityStarted(activity: Activity) = Unit
        override fun onActivityResumed(activity: Activity) = Unit
        override fun onActivityPaused(activity: Activity) = Unit
        override fun onActivityStopped(activity: Activity) = Unit
        override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit
        override fun onActivityDestroyed(activity: Activity) = Unit
    }

    override fun before() {
        // A one-time CI dismissal can precede the test by minutes. Re-establish
        // the unsecured keyguard precondition without removing any credential.
        shell("input keyevent KEYCODE_WAKEUP")
        val keyguard = app.getSystemService(KeyguardManager::class.java)
        if (!keyguard.isDeviceSecure) {
            shell("wm dismiss-keyguard")
            val deadline = SystemClock.elapsedRealtime() + 5_000
            while (keyguard.isKeyguardLocked && SystemClock.elapsedRealtime() < deadline) {
                SystemClock.sleep(50)
            }
        }
        app.registerActivityLifecycleCallbacks(callbacks)
    }

    private fun shell(command: String) {
        ParcelFileDescriptor.AutoCloseInputStream(
            instrumentation.uiAutomation.executeShellCommand(command),
        ).use { it.readBytes() }
    }

    override fun after() = app.unregisterActivityLifecycleCallbacks(callbacks)
}
