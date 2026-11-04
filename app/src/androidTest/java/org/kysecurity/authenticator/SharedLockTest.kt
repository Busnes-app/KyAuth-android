package org.kysecurity.authenticator

import android.content.Context
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
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
import org.kysecurity.authenticator.mfa.MfaChallenge
import org.kysecurity.authenticator.mfa.MfaPushChallengeStore
import org.kysecurity.authenticator.pairing.PairedAccount
import org.kysecurity.authenticator.pairing.PairingStore
import org.kysecurity.authenticator.security.AppLockManager
import org.kysecurity.authenticator.security.SecurityWipe
import org.kysecurity.authenticator.totp.TotpEntry
import org.kysecurity.authenticator.totp.TotpVault
import java.io.File

/** Several KyAuth windows share one lock and one vault file. Fake unlocked state; no biometric prompt. */
@RunWith(AndroidJUnit4::class)
class SharedLockTest {
    @get:org.junit.Rule val showOverKeyguard = ShowOverKeyguard()

    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val file = File(context.filesDir, "totp_vault.bin")
    private val key = ByteArray(32) { 9 }
    private val x = TotpEntry("Entry X", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", id = "x")
    private val y = TotpEntry("Entry Y", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", id = "y")
    private val z = TotpEntry("Entry Z", "KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU", id = "z")
    private var before: ByteArray? = null

    @Before fun setup() {
        before = if (file.exists()) file.readBytes() else null
        PairingStore(context).save(PairedAccount("https://example.test", "fixture-device", "Fixture", username = "fixture-user"))
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            instrumentation.uiAutomation.grantRuntimePermission(context.packageName, android.Manifest.permission.POST_NOTIFICATIONS)
        }
        TotpVault.save(file, key, listOf(x))
        unlock()
    }

    @After fun cleanup() {
        AppLockManager.lock()
        MfaPushChallengeStore(context).clear()
        PairingStore(context).clear()
        before?.let(file::writeBytes) ?: file.delete()
    }

    private fun unlock() = instrumentation.runOnMainSync {
        for ((field, value) in mapOf("activeVaultKey" to key.copyOf(), "isUnlocked" to true)) {
            AppLockManager::class.java.getDeclaredField(field).apply { isAccessible = true }.set(AppLockManager, value)
        }
    }

    private fun call(activity: MainActivity, name: String, vararg args: Pair<Class<*>, Any?>): Any? =
        MainActivity::class.java.getDeclaredMethod(name, *args.map { it.first }.toTypedArray())
            .apply { isAccessible = true }.invoke(activity, *args.map { it.second }.toTypedArray())

    private fun texts(view: View): List<String> = buildList {
        if (view is TextView) add(view.text.toString())
        if (view is ViewGroup) for (i in 0 until view.childCount) addAll(texts(view.getChildAt(i)))
    }

    private fun shown(activity: MainActivity) = texts(activity.window.decorView)

    @Suppress("UNCHECKED_CAST")
    private fun entries(activity: MainActivity) = MainActivity::class.java.getDeclaredField("totpEntries")
        .apply { isAccessible = true }.get(activity) as List<TotpEntry>

    /** A starts B as a second window, which stops A and locks; unlock again and open the vault in both, as two resumed windows would. */
    @Suppress("UNCHECKED_CAST")
    private fun twoOpenWindows(body: (MainActivity, MainActivity) -> Unit) {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            lateinit var a: MainActivity
            scenario.onActivity { a = it; it.startActivity(android.content.Intent(it, MainActivity::class.java)) }
            val windows = MainActivity::class.java.getDeclaredField("windows").apply { isAccessible = true }.get(null) as Set<MainActivity>
            val deadline = android.os.SystemClock.elapsedRealtime() + 10_000
            var second: MainActivity? = null
            while (second == null) {
                check(android.os.SystemClock.elapsedRealtime() < deadline) { "The second window never started" }
                instrumentation.waitForIdleSync()
                instrumentation.runOnMainSync { second = windows.firstOrNull { it !== a && it.lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED) } }
                if (second == null) android.os.SystemClock.sleep(50)
            }
            val b = checkNotNull(second)
            try {
                unlock()
                instrumentation.runOnMainSync {
                    for (window in listOf(a, b)) {
                        call(window, "loadTotpEntries")
                        call(window, "renderContent")
                    }
                    body(a, b)
                }
            } finally {
                instrumentation.runOnMainSync { b.finish() }
                instrumentation.waitForIdleSync()
            }
        }
    }

    @Test fun lockingOneWindowClearsTheOther() = twoOpenWindows { a, b ->
        assertTrue(shown(a).contains(x.title))
        call(b, "lockSensitiveState")
        assertTrue(entries(a).isEmpty())
        assertFalse(shown(a).contains(x.title))
    }

    @Test fun aWindowsOlderListNeverOverwritesAnotherWindowsChange() = twoOpenWindows { a, b ->
        call(a, "addTotpEntry", TotpEntry::class.java to y)
        call(b, "addTotpEntry", TotpEntry::class.java to z) // b still shows only X
        assertEquals(listOf(x, y, z), TotpVault.load(file, key))
    }

    @Suppress("UNCHECKED_CAST")
    @Test fun editingAnEntryDeletedInAnotherWindowIsRefused() = twoOpenWindows { a, b ->
        call(a, "addTotpEntry", TotpEntry::class.java to y)
        call(b, "showEditTotpDialog", TotpEntry::class.java to y.copy()) // b's list never had Y; its editor came from a's
        TotpVault.save(file, key, listOf(x)) // Y deleted elsewhere
        val dialog = (MainActivity::class.java.getDeclaredField("openDialogs").apply { isAccessible = true }.get(b) as Set<AlertDialog>).single()
        (find(checkNotNull(dialog.window).decorView) { it is Button && it.text.toString() == "Save" } as Button).performClick()
        assertEquals(listOf(x), TotpVault.load(file, key))
        assertTrue(dialog.isShowing)
    }

    private fun find(view: View, match: (View) -> Boolean): View? = when {
        match(view) -> view
        view is ViewGroup -> (0 until view.childCount).firstNotNullOfOrNull { find(view.getChildAt(it), match) }
        else -> null
    }

    private fun challenge(lifetimeMs: Long) = MfaChallenge(
        challengeId = "c1", matchDigits = "42", decoyDigits = listOf("17"), serverUrl = "https://example.test",
        username = "fixture-user", purpose = "login", expiresAtEpochMs = System.currentTimeMillis() + lifetimeMs,
    )

    @Test fun aRequestArrivingOnSettingsShowsOnVault() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                MainActivity::class.java.getDeclaredField("activeTab").apply { isAccessible = true }.set(activity, MainActivity.Tab.SETTINGS)
                call(activity, "renderContent")
            }
            MfaPushChallengeStore(context).save(challenge(60_000))
            instrumentation.waitForIdleSync()
            scenario.onActivity { assertTrue(shown(it).contains("Sign-in request")) }
        }
    }

    @Test fun requestsStillShowLiveAfterPushStateIsCleared() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            SecurityWipe.clearPush(context) // what Unpair does, before a new pairing
            MfaPushChallengeStore(context).save(challenge(60_000))
            instrumentation.waitForIdleSync()
            scenario.onActivity { assertTrue(shown(it).contains("Sign-in request")) }
        }
    }

    @Test fun anExpiredRequestOnTheLockScreenGivesBackTheUnlockScreen() {
        instrumentation.runOnMainSync { AppLockManager.lock() }
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                MfaPushChallengeStore(context).save(challenge(2_500))
                call(activity, "loadPendingPushChallenge")
                call(activity, "renderContent")
                assertTrue(shown(activity).contains("Sign-in request"))
            }
            Thread.sleep(4_000)
            scenario.onActivity { activity ->
                assertFalse(shown(activity).contains("Sign-in request"))
                assertTrue(shown(activity).contains(activity.getString(R.string.unlock_your_vault)))
            }
        }
    }
}
