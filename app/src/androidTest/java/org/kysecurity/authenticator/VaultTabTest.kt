package org.kysecurity.authenticator

import android.content.Context
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.authenticator.mfa.MfaChallenge
import org.kysecurity.authenticator.mfa.MfaPushChallengeStore
import org.kysecurity.authenticator.pairing.PairedAccount
import org.kysecurity.authenticator.pairing.PairingStore
import org.kysecurity.authenticator.security.AppLockManager

/** Fake unlocked state; does not simulate biometric authentication. */
@RunWith(AndroidJUnit4::class)
class VaultTabTest {
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
        MfaPushChallengeStore(context).clear()
        PairingStore(context).clear()
    }

    private fun texts(view: View): List<String> = buildList {
        if (view is TextView) add(view.text.toString())
        if (view is ViewGroup) for (i in 0 until view.childCount) addAll(texts(view.getChildAt(i)))
    }

    private fun challenge(expiresInMs: Long, purpose: String = "login") = MfaChallenge(
        challengeId = "c1", matchDigits = "42", decoyDigits = listOf("17"),
        serverUrl = "https://example.test", username = "fixture-user", purpose = purpose,
        expiresAtEpochMs = System.currentTimeMillis() + expiresInMs,
    )

    @Test fun stepUpRequestShowsSensitiveActionTitle() {
        MfaPushChallengeStore(context).save(challenge(60_000, "step_up"))
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                assertTrue(texts(activity.window.decorView).contains("Confirm a sensitive action"))
            }
        }
    }

    @Test fun pendingRequestShowsWithNoTotpEntries() {
        MfaPushChallengeStore(context).save(challenge(60_000))
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val shown = texts(activity.window.decorView)
                assertTrue(shown.contains("Sign-in request"))
                assertTrue(shown.contains("No codes yet"))
                assertTrue(shown.indexOf("Sign-in request") < shown.indexOf("No codes yet"))
                assertTrue(shown.contains("Vault"))
                assertFalse(shown.contains("Push MFA"))
                assertFalse(shown.contains("Passwords"))
            }
        }
    }

    @Test fun expiredRequestIsClearedAndNotShown() {
        MfaPushChallengeStore(context).save(challenge(-1_000))
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                assertFalse(texts(activity.window.decorView).contains("Sign-in request"))
            }
        }
        assertNull(MfaPushChallengeStore(context).load())
    }

    @Test fun expiredPendingChallengeIsDroppedAtRender() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val expired = challenge(-1_000)
                val field = MainActivity::class.java.getDeclaredField("pendingChallenge").apply { isAccessible = true }
                field.set(activity, expired)
                // save, not load: load() would drop the expired challenge itself.
                MfaPushChallengeStore(context).save(expired)
                MainActivity::class.java.getDeclaredMethod("renderContent").apply { isAccessible = true }.invoke(activity)
                assertFalse(texts(activity.window.decorView).contains("Sign-in request"))
                assertNull(field.get(activity))
                val raw = context.getSharedPreferences("mfa_push_challenge", Context.MODE_PRIVATE).getString("challenge", null)
                assertNull(raw)
            }
        }
    }
}
