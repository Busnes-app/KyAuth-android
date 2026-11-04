package org.kysecurity.authenticator

import android.content.Context
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.authenticator.pairing.PairedAccount
import org.kysecurity.authenticator.pairing.PairingStore
import org.kysecurity.authenticator.security.AppLockManager
import org.kysecurity.authenticator.totp.TotpEntry
import org.kysecurity.authenticator.totp.TotpVault
import java.io.File

/** KyAuth without KyIdentity (owner decision Q1 A). Fake unlocked state; no biometric prompt. */
@RunWith(AndroidJUnit4::class)
class UnpairedVaultTest {
    @get:org.junit.Rule val showOverKeyguard = ShowOverKeyguard()

    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val file = File(context.filesDir, "totp_vault.bin")
    private val key = ByteArray(32) { 9 }
    private val entry = TotpEntry("Local fixture", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", id = "local-fixture")
    private var before: ByteArray? = null

    @Before fun setup() {
        before = if (file.exists()) file.readBytes() else null
        file.delete()
        PairingStore(context).clear()
        localUse(false)
        unlock()
    }

    @After fun cleanup() {
        AppLockManager.lock()
        PairingStore(context).clear()
        localUse(false)
        before?.let(file::writeBytes) ?: file.delete()
    }

    private fun localUse(on: Boolean) =
        context.getSharedPreferences("app_lock", Context.MODE_PRIVATE).edit().putBoolean("local_use", on).commit()

    private fun unlock() = InstrumentationRegistry.getInstrumentation().runOnMainSync {
        for ((field, value) in mapOf("activeVaultKey" to key.copyOf(), "isUnlocked" to true)) {
            AppLockManager::class.java.getDeclaredField(field).apply { isAccessible = true }.set(AppLockManager, value)
        }
    }

    private fun texts(view: View): List<String> = buildList {
        if (view is TextView) add(view.text.toString())
        if (view is ViewGroup) for (i in 0 until view.childCount) addAll(texts(view.getChildAt(i)))
    }

    private fun button(view: View, label: String): Button = checkNotNull(find(view) { it is Button && it.text.toString() == label }) as Button

    private fun find(view: View, match: (View) -> Boolean): View? = when {
        match(view) -> view
        view is ViewGroup -> (0 until view.childCount).firstNotNullOfOrNull { find(view.getChildAt(it), match) }
        else -> null
    }

    private fun showSettings(activity: MainActivity) {
        MainActivity::class.java.getDeclaredField("activeTab").apply { isAccessible = true }.set(activity, MainActivity.Tab.SETTINGS)
        MainActivity::class.java.getDeclaredMethod("renderContent").apply { isAccessible = true }.invoke(activity)
    }

    @Test fun freshInstallOffersKyAuthWithoutKyIdentity() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val root = activity.window.decorView
                assertTrue(texts(root).contains("Connect your account"))
                button(root, activity.getString(R.string.use_without_kyidentity)).performClick()
                val shown = texts(activity.window.decorView)
                assertTrue(shown.contains("No codes yet"))
                assertFalse(shown.contains("Connect your account"))
            }
        }
        assertTrue(context.getSharedPreferences("app_lock", Context.MODE_PRIVATE).getBoolean("local_use", false))
    }

    @Test fun unpairedVaultShowsCodesAndOffersPairingInsteadOfPairedSettings() {
        TotpVault.save(file, key, listOf(entry))
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                assertTrue(texts(activity.window.decorView).contains(entry.title))
                showSettings(activity)
                val settings = texts(activity.window.decorView)
                assertTrue(settings.contains(activity.getString(R.string.pair_with_kyidentity)))
                assertFalse(settings.contains(activity.getString(R.string.unpair_account)))
                assertFalse(settings.contains("Sign-in request delivery"))
                assertTrue(settings.contains(activity.getString(R.string.enable_pin)))

                button(activity.window.decorView, activity.getString(R.string.pair_with_kyidentity)).performClick()
                assertTrue(texts(activity.window.decorView).contains("Connect your account"))
                button(activity.window.decorView, activity.getString(R.string.use_without_kyidentity)).performClick()
                assertTrue(texts(activity.window.decorView).contains(activity.getString(R.string.pair_with_kyidentity)))

                // Back leaves the pairing screen for the vault, as the button does.
                button(activity.window.decorView, activity.getString(R.string.pair_with_kyidentity)).performClick()
                activity.onBackPressedDispatcher.onBackPressed()
                assertTrue(texts(activity.window.decorView).contains(activity.getString(R.string.pair_with_kyidentity)))
            }
        }
    }

    @Test fun unpairKeepsTheVaultReachable() {
        TotpVault.save(file, key, listOf(entry))
        PairingStore(context).save(PairedAccount("https://example.test", "fixture-device", "Fixture"))
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                MainActivity::class.java.getDeclaredMethod("clearPairing").apply { isAccessible = true }.invoke(activity)
                val shown = texts(activity.window.decorView)
                assertTrue(shown.contains(activity.getString(R.string.unlock_your_vault)))
                assertTrue(shown.contains(activity.getString(R.string.unlock_unpaired)))
                assertFalse(shown.contains("Connect your account"))
            }
        }
    }
}
