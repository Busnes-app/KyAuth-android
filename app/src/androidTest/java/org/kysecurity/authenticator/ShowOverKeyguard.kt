package org.kysecurity.authenticator

import android.app.Activity
import android.app.Application
import android.os.Bundle
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.rules.ExternalResource

/**
 * Test-only: shows [MainActivity] above the keyguard, so a keyguard on the test device cannot
 * stop the activity and trip the lock-on-stop behaviour these tests assert on. The app itself
 * never shows over the lock screen. CI also sets no PIN while these run (see [SecureLockScreen]).
 */
class ShowOverKeyguard : ExternalResource() {
    private val app = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as Application

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

    override fun before() = app.registerActivityLifecycleCallbacks(callbacks)

    override fun after() = app.unregisterActivityLifecycleCallbacks(callbacks)
}
