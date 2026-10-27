package org.kysecurity.authenticator

import android.content.Context
import android.content.ClipData
import android.content.ClipboardManager
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.authenticator.mfa.MfaChallenge
import org.kysecurity.authenticator.mfa.MfaPushChallengeStore
import org.kysecurity.authenticator.pairing.PairedAccount
import org.kysecurity.authenticator.pairing.PairingStore
import org.kysecurity.authenticator.security.AppLockManager
import org.kysecurity.authenticator.totp.TotpEntry
import org.kysecurity.authenticator.totp.TotpVault
import java.io.File

/** Fake unlocked state; does not simulate biometric authentication. */
@RunWith(AndroidJUnit4::class)
class VaultTabTest {
    @get:org.junit.Rule val showOverKeyguard = ShowOverKeyguard()

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

    private fun views(view: View): List<View> = buildList {
        add(view)
        if (view is ViewGroup) for (i in 0 until view.childCount) addAll(views(view.getChildAt(i)))
    }

    @Suppress("UNCHECKED_CAST")
    private fun dialog(activity: MainActivity) = (MainActivity::class.java.getDeclaredField("openDialogs")
        .apply { isAccessible = true }.get(activity) as Set<AlertDialog>).single { it.isShowing }

    private fun awaitWindowFocus(scenario: ActivityScenario<MainActivity>) {
        val deadline = android.os.SystemClock.elapsedRealtime() + 10_000
        while (true) {
            var focused = false
            scenario.onActivity { focused = it.window.decorView.hasWindowFocus() }
            if (focused) return
            check(android.os.SystemClock.elapsedRealtime() < deadline) {
                val keyguard = context.getSystemService(android.app.KeyguardManager::class.java)
                val owners = android.os.ParcelFileDescriptor.AutoCloseInputStream(
                    InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand("dumpsys -t 2 window"),
                ).use { stream ->
                    stream.bufferedReader().readLines().filter {
                        it.contains("mCurrentFocus") || it.contains("mFocusedApp") || it.contains("mFocusedWindow")
                    }.joinToString("; ")
                }
                "Activity window never gained focus (keyguardLocked=${keyguard.isKeyguardLocked}, secure=${keyguard.isDeviceSecure}; $owners)"
            }
            android.os.SystemClock.sleep(50)
        }
    }

    @Test fun weakLegacyEntryStaysVisibleUncopyableAndEditableWithoutChangingItsSecret() {
        val file = File(context.filesDir, "totp_vault.bin")
        val before = if (file.exists()) file.readBytes() else null
        val key = ByteArray(32) { 9 }
        val legacy = TotpEntry("Legacy fixture", " jbsw y3dp ehpk 3pxp ", notes = "Retained notes", id = "legacy-fixture")
        val strong = TotpEntry("Strong fixture", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", id = "strong-fixture")
        try {
            TotpVault.save(file, key, listOf(legacy, strong))
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                // Android refuses clipboard reads until the window, not just the activity, is focused.
                awaitWindowFocus(scenario)
                scenario.onActivity { activity ->
                    val shown = texts(activity.window.decorView)
                    assertTrue(shown.contains(legacy.title))
                    assertTrue(shown.contains(strong.title))
                    assertTrue(shown.contains("Retained notes"))
                    assertTrue(shown.contains(activity.getString(R.string.totp_secret_too_short)))
                    val code = views(activity.window.decorView).filterIsInstance<TextView>()
                        .single { it.text.toString() == activity.getString(R.string.totp_code_unavailable) }
                    assertFalse(code.isClickable)
                    val clipboard = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    clipboard.setPrimaryClip(ClipData.newPlainText("Fixture", "unchanged"))
                    code.performClick() // Even a programmatic click must not copy a weak code.
                    assertEquals("unchanged", clipboard.primaryClip?.getItemAt(0)?.text.toString())

                    MainActivity::class.java.getDeclaredMethod("showEditTotpDialog", TotpEntry::class.java)
                        .apply { isAccessible = true }.invoke(activity, legacy)
                    val form = views(checkNotNull(dialog(activity).window).decorView)
                    form.filterIsInstance<EditText>().single { it.hint.toString() == "Notes (optional)" }
                        .setText("Set up again with the provider")
                    form.filterIsInstance<Button>().single { it.text.toString() == "Save" }.performClick()
                    val saved = TotpVault.load(file, key)
                    assertEquals(listOf(legacy.copy(notes = "Set up again with the provider"), strong), saved)

                    MainActivity::class.java.getDeclaredMethod("showEditTotpDialog", TotpEntry::class.java)
                        .apply { isAccessible = true }.invoke(activity, saved.first())
                    val edit = dialog(activity)
                    val editForm = views(checkNotNull(edit.window).decorView)
                    val replacement = editForm.filterIsInstance<EditText>()
                        .single { it.hint.toString() == "Secret Key (Base32)" }
                    replacement.setText("GE")
                    editForm.filterIsInstance<Button>().single { it.text.toString() == "Save" }.performClick()
                    assertTrue(edit.isShowing)
                    assertEquals(activity.getString(R.string.totp_secret_too_short), replacement.error.toString())
                    assertEquals(saved, TotpVault.load(file, key))
                }
            }
        } finally {
            if (before == null) file.delete() else file.writeBytes(before)
        }
    }

    @Test fun manualImportRejectsShortSecretInlineAndPreservesTheFormForCorrection() {
        val file = File(context.filesDir, "totp_vault.bin")
        val before = if (file.exists()) file.readBytes() else null
        val key = ByteArray(32) { 9 }
        try {
            TotpVault.save(file, key, emptyList())
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                scenario.onActivity { activity ->
                    MainActivity::class.java.getDeclaredMethod("showAddTotpDialog")
                        .apply { isAccessible = true }.invoke(activity)
                    val open = dialog(activity)
                    val form = views(checkNotNull(open.window).decorView)
                    form.filterIsInstance<EditText>().single { it.hint.toString() == "Account Name (e.g. GitHub)" }
                        .setText("Imported fixture")
                    val secret = form.filterIsInstance<EditText>().single { it.hint.toString() == "Secret Key (Base32)" }
                    secret.setText("GE")
                    val save = form.filterIsInstance<Button>().single { it.text.toString() == "Save" }
                    save.performClick()
                    assertTrue(open.isShowing)
                    assertEquals("GE", secret.text.toString())
                    assertEquals(activity.getString(R.string.totp_secret_too_short), secret.error.toString())
                    assertEquals(emptyList<TotpEntry>(), TotpVault.load(file, key))
                    secret.setText("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
                    save.performClick()
                    assertFalse(open.isShowing)
                    assertEquals("Imported fixture", TotpVault.load(file, key).single().title)
                }
            }
        } finally {
            if (before == null) file.delete() else file.writeBytes(before)
        }
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
                assertTrue(shown.contains("Account: fixture-user\nServer: example.test"))
                assertTrue(shown.any { Regex("Expires in (1:00|0:[0-5]\\d)").matches(it) })
                assertFalse(shown.any { "User:" in it || "seconds" in it || "https://" in it || "Fixture" in it })
                assertTrue(shown.contains("Vault"))
                assertFalse(shown.contains("Push MFA"))
                assertFalse(shown.contains("Passwords"))
            }
        }
    }

    // A legacy push names no account; without a username from pairing the card names none either.
    @Test fun requestWithoutAnyUsernameNeverShowsThePhoneAsTheUser() {
        MfaPushChallengeStore(context).save(challenge(60_000).copy(username = null))
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val shown = texts(activity.window.decorView)
                assertTrue(shown.contains("Server: example.test"))
                assertFalse(shown.any { "Account:" in it || "User:" in it || "Fixture" in it })
            }
        }
    }

    @Test fun requestCountsDownToExpiredAndDisablesApprove() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                // Start the short expiry after startup; a slow emulator can take longer than 2.5 s to launch.
                MfaPushChallengeStore(context).save(challenge(2_500))
                for (method in listOf("loadPendingPushChallenge", "renderContent")) {
                    MainActivity::class.java.getDeclaredMethod(method).apply { isAccessible = true }.invoke(activity)
                }
                assertTrue(texts(activity.window.decorView).any { it.startsWith("Expires in 0:0") })
                assertTrue(approveButton(activity.window.decorView)!!.isEnabled)
            }
            Thread.sleep(4_000)
            scenario.onActivity { activity ->
                val shown = texts(activity.window.decorView)
                assertTrue(shown.contains("Expired"))
                assertFalse(approveButton(activity.window.decorView)!!.isEnabled)
            }
        }
    }

    private fun approveButton(view: View): Button? = when {
        view is Button && view.text.toString() == "Approve request" -> view
        view is ViewGroup -> (0 until view.childCount).firstNotNullOfOrNull { approveButton(view.getChildAt(it)) }
        else -> null
    }

    @Test fun lockedRequestShowsOnLockScreenWithoutTheVault() {
        InstrumentationRegistry.getInstrumentation().runOnMainSync { AppLockManager.lock() }
        MfaPushChallengeStore(context).save(challenge(60_000))
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val shown = texts(activity.window.decorView)
                assertTrue(shown.contains("Sign-in request"))
                assertTrue(shown.contains("Approve request"))
                assertFalse(shown.contains("No codes yet"))
                assertFalse(shown.contains(activity.getString(R.string.unlock_your_vault)))
            }
        }
    }

    @Test fun lateClearSparesANewerRequest() {
        val store = MfaPushChallengeStore(context)
        store.save(challenge(60_000).copy(challengeId = "newer"))
        store.clear("c1")
        assertTrue(store.load()?.challengeId == "newer")
        store.clear("newer")
        assertNull(store.load())
    }

    @Test fun pairingChangeClearsTheStoredRequest() {
        MfaPushChallengeStore(context).save(challenge(60_000))
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                MainActivity::class.java.getDeclaredMethod("clearPairing").apply { isAccessible = true }.invoke(activity)
            }
        }
        assertNull(MfaPushChallengeStore(context).load())
    }

    // Answered elsewhere (e.g. by the activity this one replaced): no second prompt, card dropped.
    @Test fun requestNoLongerStoredIsDroppedWithoutAPrompt() {
        val shown = challenge(60_000)
        MfaPushChallengeStore(context).save(shown)
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                MfaPushChallengeStore(context).clear()
                MainActivity::class.java.getDeclaredMethod(
                    "respondToChallenge", MfaChallenge::class.java, PairedAccount::class.java,
                    Boolean::class.javaPrimitiveType, String::class.java,
                ).apply { isAccessible = true }.invoke(activity, shown, PairingStore(context).account(), false, "")
                assertFalse(texts(activity.window.decorView).contains("Sign-in request"))
                assertTrue(activity.supportFragmentManager.fragments.none { it.javaClass.name.contains("Biometric") })
            }
        }
    }

    // The activity a rotation destroyed finishes the answer: this one drops the card with no resume.
    @Test fun requestClearedElsewhereLeavesTheScreen() {
        MfaPushChallengeStore(context).save(challenge(60_000))
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { assertTrue(texts(it.window.decorView).contains("Sign-in request")) }
            Thread { MfaPushChallengeStore(context).clear("c1") }.apply { start(); join() }
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            scenario.onActivity { assertFalse(texts(it.window.decorView).contains("Sign-in request")) }
        }
    }

    // B arrives while A's answer is in flight; A's completion must not hide B.
    @Test fun answerCompletionKeepsANewerRequestOnScreen() {
        MfaPushChallengeStore(context).save(challenge(60_000))
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            MfaPushChallengeStore(context).save(challenge(60_000, "step_up").copy(challengeId = "c2"))
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            scenario.onActivity { assertTrue(texts(it.window.decorView).contains("Confirm a sensitive action")) }
            MfaPushChallengeStore(context).clear("c1") // what the response thread does for A
            scenario.onActivity { activity ->
                MainActivity::class.java.getDeclaredMethod("onAnswerAccepted", Boolean::class.javaPrimitiveType)
                    .apply { isAccessible = true }.invoke(activity, true)
                assertTrue(texts(activity.window.decorView).contains("Confirm a sensitive action"))
            }
        }
        assertTrue(MfaPushChallengeStore(context).load()?.challengeId == "c2")
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
