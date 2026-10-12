package org.kysecurity.authenticator.security

import android.view.WindowManager
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.authenticator.MainActivity

// Debug builds allow capture, so the policy is passed in rather than read from BuildConfig.
@RunWith(AndroidJUnit4::class)
class SecureWindowTest {
    @get:org.junit.Rule val showOverKeyguard = org.kysecurity.authenticator.ShowOverKeyguard()

    private fun secureAfter(allowScreenshots: Boolean): Boolean {
        var secure = false
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                secureWindow(activity.window, allowScreenshots)
                secure = activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0
            }
        }
        return secure
    }

    @Test fun releasePolicySetsFlagSecure() = assertEquals(true, secureAfter(allowScreenshots = false))

    @Test fun debugPolicyLeavesCaptureAllowed() = assertEquals(false, secureAfter(allowScreenshots = true))
}
