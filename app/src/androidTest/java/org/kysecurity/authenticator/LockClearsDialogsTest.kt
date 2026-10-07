package org.kysecurity.authenticator

import android.content.Context
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.authenticator.pairing.PairedAccount
import org.kysecurity.authenticator.pairing.PairingStore
import org.kysecurity.authenticator.security.AppLockManager

/** Fake unlocked state; does not simulate biometric authentication. */
@RunWith(AndroidJUnit4::class)
class LockClearsDialogsTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Before fun setup() {
        PairingStore(context).save(PairedAccount("https://example.test", "fixture-device", "Fixture"))
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            instrumentation.uiAutomation.grantRuntimePermission(context.packageName, android.Manifest.permission.POST_NOTIFICATIONS)
        }
        instrumentation.runOnMainSync {
            for ((field, value) in mapOf("activeVaultKey" to ByteArray(32) { 9 }, "isUnlocked" to true)) {
                AppLockManager::class.java.getDeclaredField(field).apply { isAccessible = true }.set(AppLockManager, value)
            }
        }
    }

    @After fun cleanup() {
        AppLockManager.lock()
        PairingStore(context).clear()
    }

    @Suppress("UNCHECKED_CAST")
    private fun dialogs(activity: MainActivity) = MainActivity::class.java.getDeclaredField("openDialogs")
        .apply { isAccessible = true }.get(activity) as Set<AlertDialog>

    private fun inputs(view: View): List<EditText> = buildList {
        if (view is EditText) add(view)
        if (view is ViewGroup) for (i in 0 until view.childCount) addAll(inputs(view.getChildAt(i)))
    }

    private fun secretField(activity: MainActivity): Pair<AlertDialog, EditText> {
        MainActivity::class.java.getDeclaredMethod("showAddTotpDialog").apply { isAccessible = true }.invoke(activity)
        val dialog = dialogs(activity).single()
        val input = inputs(checkNotNull(dialog.window).decorView).single { it.hint.toString() == "Secret Key (Base32)" }
        input.setText("JBSWY3DPEHPK3PXP")
        return dialog to input
    }

    @Test fun backgroundClearsAndDismissesUnsavedForm() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            lateinit var dialog: AlertDialog
            lateinit var input: EditText
            scenario.onActivity { activity ->
                assertTrue("Fixture activity must be unlocked", AppLockManager.isUnlocked())
                secretField(activity).let { dialog = it.first; input = it.second }
            }
            scenario.moveToState(Lifecycle.State.CREATED)
            // ActivityScenario observes super.onStop before our override finishes clearing views.
            InstrumentationRegistry.getInstrumentation().runOnMainSync {
                assertFalse(AppLockManager.isUnlocked())
                assertFalse(dialog.isShowing)
                assertEquals("", input.text.toString())
            }
        }
    }

    @Test fun expiredInputLocksAndClearsAnUnsavedForm() {
        context.getSharedPreferences("app_lock", Context.MODE_PRIVATE).edit().putInt("idle_lock_minutes", 5).commit()
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val (dialog, input) = secretField(activity)
                AppLockManager.idleLock.reset()
                AppLockManager.idleLock.activity(android.os.SystemClock.elapsedRealtime() - 300_001, 300_000)
                val result = MainActivity::class.java.getDeclaredMethod("recordVaultActivity")
                    .apply { isAccessible = true }.invoke(activity)
                assertEquals(false, result)
                assertFalse(AppLockManager.isUnlocked())
                assertFalse(dialog.isShowing)
                assertEquals("", input.text.toString())
            }
        }
    }
}
