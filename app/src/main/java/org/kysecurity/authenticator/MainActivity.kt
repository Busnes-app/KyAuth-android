package org.kysecurity.authenticator

import android.Manifest
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.DialogInterface
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.text.InputFilter
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputMethodManager
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.Space
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import org.kysecurity.authenticator.mfa.IncomingPush
import org.kysecurity.authenticator.mfa.MfaChallenge
import org.kysecurity.authenticator.mfa.MfaMessage
import org.kysecurity.authenticator.mfa.MfaPushChallengeStore
import org.kysecurity.authenticator.mfa.MfaResponseClient
import org.kysecurity.authenticator.mfa.MfaResponseResult
import org.kysecurity.authenticator.pairing.AttestationChallenge
import org.kysecurity.authenticator.pairing.attestationSummary
import org.kysecurity.authenticator.pairing.DeviceSigningKey
import org.kysecurity.authenticator.pairing.PairedAccount
import org.kysecurity.authenticator.pairing.PairingClient
import org.kysecurity.authenticator.pairing.PairingStore
import org.kysecurity.authenticator.pairing.QrPairing
import org.kysecurity.authenticator.pairing.QrPairingParser
import org.kysecurity.authenticator.signon.KyIdentityAccount
import org.kysecurity.authenticator.signon.PendingAddAccount
import org.kysecurity.authenticator.pairing.ChannelPush
import org.kysecurity.authenticator.pairing.PushCredential
import org.kysecurity.authenticator.pairing.PushRefreshClient
import org.kysecurity.authenticator.pairing.DeviceRevokeClient
import org.kysecurity.authenticator.pairing.PushStore
import org.kysecurity.authenticator.pairing.UnifiedPushRegistrar
import org.kysecurity.authenticator.security.RemovedPasskey
import org.kysecurity.authenticator.security.SecurityWipe
import org.kysecurity.authenticator.security.secureWindow
import org.kysecurity.authenticator.security.IdleLock
import org.kysecurity.authenticator.security.AppLockManager
import org.kysecurity.authenticator.security.VaultUnlockPrompt
import org.kysecurity.authenticator.security.PinFailurePolicy
import org.kysecurity.authenticator.security.PinPolicy
import org.kysecurity.authenticator.totp.TotpVault
import org.kysecurity.authenticator.totp.TotpVaultException
import org.kysecurity.authenticator.totp.TotpEntry
import org.kysecurity.authenticator.totp.TotpDisplay
import org.kysecurity.authenticator.totp.TotpUriParser
import java.io.File
import java.net.URI
import java.util.UUID
import java.util.concurrent.Executor
import kotlin.math.max
import kotlin.math.min

private const val STATE_ACTIVE_TAB = "active_tab"
private const val STATE_DEMO = "demo"
private const val VAULT_UNREADABLE = "The TOTP vault could not be read. KyAuth stays locked and has not changed it."

class MainActivity : AppCompatActivity() {
    private lateinit var store: PairingStore
    private lateinit var qrScanner: QrScanner
    private val executor: Executor by lazy { ContextCompat.getMainExecutor(this) }
    private val handler = Handler(Looper.getMainLooper())
    private val openDialogs = mutableSetOf<AlertDialog>()
    private val idlePreferences by lazy { getSharedPreferences("app_lock", MODE_PRIVATE) }
    private fun idleMinutes() = IdleLock.validatedMinutes(idlePreferences.getInt("idle_lock_minutes", 5))
    private fun idleTimeoutMillis() = idleMinutes() * 60_000L

    private var activeTab = Tab.VAULT
    // Never written to storage; the demo reads and writes no stored state.
    private var demo = false
    private var nextDemoPushAt = 0L
    private var pendingChallenge: MfaChallenge? = null
    private var challengeObserver: android.content.SharedPreferences.OnSharedPreferenceChangeListener? = null
    private var pendingTotpEntry: TotpEntry? = null
    /** A pairing scan result for the enrollment screen to act on: text, or failure. */
    private var scannedPairing: Result<String>? = null
    private var askedForDistributor = false
    private var totpEntries = mutableListOf<TotpEntry>()
    private var copiedSensitiveLabel: String? = null
    private var isVaultLoading = false
    private var vaultLoadGeneration: Long? = null
    /** [totpEntries] came from a successful load; only then may it be saved. */
    private var vaultLoaded = false
    private data class TotpViews(
        val entry: TotpEntry,
        val code: TextView,
        val timer: TextView,
        val progress: ProgressBar,
    )
    private val totpViews = mutableListOf<TotpViews>()
    private val vaultFile: File by lazy { File(filesDir, "totp_vault.bin") }

    private val ticker = object : Runnable {
        override fun run() {
            if (AppLockManager.isUnlocked() && AppLockManager.idleLock.expired(android.os.SystemClock.elapsedRealtime(), idleTimeoutMillis())) {
                lockSensitiveState()
                renderContent()
            }
            if (!isVaultLoading && (AppLockManager.isUnlocked() || demo) && activeTab == Tab.VAULT) {
                updateTotpViews()
            }
            simulateDemoPush()
            handler.postDelayed(this, 1000)
        }
    }

    enum class Tab {
        VAULT, SETTINGS;

        companion object {
            fun restore(name: String?): Tab = entries.firstOrNull { it.name == name } ?: VAULT
        }
    }

    companion object {
        const val EXTRA_ADD_ACCOUNT = "add_account"
        private val TWO_DIGITS = Regex("\\d{2}")
    }

    private var addAccountResponse: android.accounts.AccountAuthenticatorResponse? = null

    // Completes the AccountManager addAccount future once pairing has produced the account.
    private fun answerAddAccountIfPossible(): Boolean {
        val response = addAccountResponse ?: return false
        val account = KyIdentityAccount.current(this) ?: return false
        addAccountResponse = null
        response.onResult(Bundle().apply {
            putString(android.accounts.AccountManager.KEY_ACCOUNT_NAME, account.name)
            putString(android.accounts.AccountManager.KEY_ACCOUNT_TYPE, account.type)
        })
        finish()
        return true
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        activeTab = Tab.restore(savedInstanceState?.getString(STATE_ACTIVE_TAB))
        demo = savedInstanceState?.getBoolean(STATE_DEMO) ?: false
        WindowCompat.setDecorFitsSystemWindows(window, false)
        if (!BuildConfig.ALLOW_SCREENSHOTS) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        RemovedPasskey.delete(this)
        store = PairingStore(this)
        if (store.account() != null && PushStore(this).transport == PushCredential.FCM) ChannelPush.resume()
        qrScanner = ChannelQrScanner.create(this, ::onQrScanned)
        addAccountResponse = PendingAddAccount.take(intent.getStringExtra(EXTRA_ADD_ACCOUNT))
        IncomingPush.ensureChannel(this)
        handler.post(ticker)
        // A request answered by the activity this one replaced, or a new push, shows up without a resume.
        challengeObserver = MfaPushChallengeStore(this).observe {
            pendingChallenge = MfaPushChallengeStore(this).load()
            if (!isDestroyed) renderContent()
        }
    }

    override fun onResume() {
        super.onResume()
        if (answerAddAccountIfPossible()) return
        if (demo) {
            renderContent()
            return
        }
        loadPendingPushChallenge()
        if (!AppLockManager.isUnlocked()) {
            // A push request is answered from the lock screen with one signing prompt; a vault
            // unlock prompt first would only add a second one.
            if (pendingChallenge == null) unlockWithPrompt(silent = true)
        } else {
            runCatching { loadTotpEntries() }.onFailure {
                lockSensitiveState()
                toast(VAULT_UNREADABLE)
            }
        }
        renderContent()
        requestNotificationPermissionIfNeeded()
        prepareUnifiedPushForPairing()
    }

    /**
     * An unpaired UnifiedPush device asks for a distributor now, not at the Pair tap: the endpoint
     * arrives asynchronously, and a KyIdentity pairing QR expires in 90 seconds.
     */
    private fun prepareUnifiedPushForPairing() {
        val push = PushStore(this)
        if (askedForDistributor || store.account() != null) return
        if (push.transport != PushCredential.UNIFIED_PUSH || push.unifiedPushCredential() != null) return
        askedForDistributor = true
        registerUnifiedPush { it?.let(::toast) }
    }

    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) {
            lockSensitiveState()
            renderContent()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        challengeObserver?.let { MfaPushChallengeStore(this).stopObserving(it) }
        if (!isChangingConfigurations) {
            addAccountResponse?.onError(android.accounts.AccountManager.ERROR_CODE_CANCELED, "Pairing cancelled")
            addAccountResponse = null
        }
        handler.removeCallbacks(ticker)
        vaultLoadGeneration = null
        dismissSensitiveDialogs()
        totpEntries.clear()
        totpViews.clear()
    }

    private fun recordVaultActivity(): Boolean {
        if (!AppLockManager.isUnlocked()) return true
        if (AppLockManager.idleLock.activity(android.os.SystemClock.elapsedRealtime(), idleTimeoutMillis())) return true
        lockSensitiveState()
        renderContent()
        return false
    }

    override fun dispatchTouchEvent(event: android.view.MotionEvent): Boolean {
        if (event.action == android.view.MotionEvent.ACTION_DOWN && !recordVaultActivity()) return true
        return super.dispatchTouchEvent(event)
    }

    override fun dispatchKeyEvent(event: android.view.KeyEvent): Boolean {
        if (event.action == android.view.KeyEvent.ACTION_DOWN && !recordVaultActivity()) return true
        return super.dispatchKeyEvent(event)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putString(STATE_ACTIVE_TAB, activeTab.name)
        outState.putBoolean(STATE_DEMO, demo)
        super.onSaveInstanceState(outState)
    }

    private fun renderContent() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(ThemeManager.color(context, R.color.ky_background))
        }
        applyRootPadding(root)

        val account = store.account()
        demo = DemoMode.active(demo, account)
        when {
            demo -> {
                if (totpEntries.isEmpty()) totpEntries = DemoMode.entries().toMutableList()
                renderDashboard(root, DemoMode.account)
            }
            account == null -> renderEnrollmentView(root)
            !AppLockManager.isUnlocked() -> renderLockScreen(root, account)
            else -> renderDashboard(root, account)
        }

        setRootContentView(root)
    }

    // ==========================================
    // 1. Enrollment / Pairing Screen
    // ==========================================

    private fun renderEnrollmentView(root: LinearLayout) {
        root.gravity = Gravity.CENTER_HORIZONTAL

        root.addView(brand("KyAuth", "SECURE ACCESS"))
        root.addView(title("Connect your account"))
        root.addView(message("Scan the 90-second QR code from KyIdentity. The pairing credential is used once and never stored."))

        val error = message("").apply { setTextColor(ThemeManager.color(context, R.color.ky_error)) }
        val progress = ProgressBar(this).apply { visibility = ProgressBar.GONE }

        val btnScan = primaryButton(getString(R.string.scan_qr)).apply {
            setOnClickListener {
                error.text = ""
                qrScanner.scan(ScanPurpose.PAIRING)
            }
        }
        scannedPairing?.let { scanned ->
            scannedPairing = null
            scanned.onFailure { error.text = getString(R.string.scan_failed) }
                .mapCatching { QrPairingParser.parse(it) }
                .onSuccess { showPairingConfirmation(it, btnScan, progress, error) }
                .onFailure { if (scanned.isSuccess) error.text = it.message ?: "Invalid KyIdentity QR code" }
        }

        val btnManual = secondaryButton("Enter code manually").apply {
            setOnClickListener { showManualPairingDialog(progress, error) }
        }

        val btnDemo = ghostButton(getString(R.string.demo_try)).apply {
            setOnClickListener { startDemo() }
        }

        root.addView(btnScan, fullWidthParams())
        root.addView(btnManual, fullWidthParams(top = 10))
        root.addView(btnDemo, fullWidthParams(top = 10))
        root.addView(progress)
        root.addView(error)
    }

    private fun showPairingConfirmation(pairing: QrPairing, triggerBtn: Button?, progress: ProgressBar, error: TextView) {
        val host = runCatching { URI(pairing.serverUrl).host }.getOrNull().orEmpty()
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.pairing_title))
            .setMessage("QR code read. Pair this device with $host?")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Pair") { _, _ ->
                // Resolved before the device key is replaced, so a missing endpoint never costs the pairing.
                val pushStore = PushStore(this)
                val transport = pushStore.transport
                val unifiedPush = pushStore.unifiedPushCredential()
                if (transport == PushCredential.UNIFIED_PUSH && unifiedPush == null) {
                    registerUnifiedPush { error.text = it ?: getString(R.string.push_waiting_for_distributor) }
                    return@setPositiveButton
                }
                authenticateWithBiometrics(
                    reason = "Pair with $host",
                    onSuccess = {
                        triggerBtn?.isEnabled = false
                        progress.visibility = ProgressBar.VISIBLE
                        Thread {
                            var keyReplaced = false
                            var push: PushCredential? = null
                            val result = runCatching {
                                push = if (transport == PushCredential.UNIFIED_PUSH) unifiedPush else ChannelPush.fcmCredential().getOrThrow()
                                val hadAccount = runCatching { store.account() != null }.getOrDefault(false)
                                keyReplaced = hadAccount
                                val key = DeviceSigningKey.regenerate(AttestationChallenge.forPairing(pairing))
                                PairingClient().register(
                                    pairing = pairing,
                                    deviceName = android.os.Build.MODEL,
                                    deviceIdentifier = store.deviceIdentifier(),
                                    push = push,
                                    publicKeyBase64 = key.publicKeyBase64,
                                    attestationChain = key.attestationChain,
                                )
                            }
                            runOnUiThread {
                                progress.visibility = ProgressBar.GONE
                                triggerBtn?.isEnabled = true
                                result.onSuccess { account ->
                                    clearPendingChallenge()
                                    store.save(account)
                                    push?.let { pushStore.markRegistered(it) }
                                    runCatching { KyIdentityAccount.sync(this@MainActivity, account) }
                                    if (answerAddAccountIfPossible()) return@onSuccess
                                    unlockWithPrompt()
                                }.onFailure {
                                    if (!keyReplaced) {
                                        error.text = it.message ?: "Pairing failed"
                                        return@onFailure
                                    }
                                    // The old key is gone, so the saved pairing cannot sign anything.
                                    clearPairing()
                                    AlertDialog.Builder(this@MainActivity)
                                        .setTitle(getString(R.string.pairing_title))
                                        .setMessage(getString(R.string.pairing_failed_key_replaced, (it.message ?: "unknown error").trimEnd('.')))
                                        .setPositiveButton("OK", null)
                                        .showKyDialog()
                                }
                            }
                        }.start()
                    },
                    onError = { error.text = it },
                )
            }
            .showKyDialog()
    }

    private fun showManualPairingDialog(progress: ProgressBar, error: TextView) {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 24)
        }
        val serverInput = EditText(this).apply { hint = "Server URL (e.g. https://auth.example.com)"; styleInput(this) }
        val tokenInput = EditText(this).apply { hint = "Pairing Token or PIN"; styleInput(this) }
        val userInput = EditText(this).apply { hint = "User ID (optional if using token)"; styleInput(this) }

        container.addView(serverInput)
        container.addView(tokenInput)
        container.addView(userInput)

        AlertDialog.Builder(this)
            .setTitle("Manual KyIdentity Pairing")
            .setView(container)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Pair") { _, _ ->
                val serverUrl = serverInput.text.toString().trim()
                val tokenOrPin = tokenInput.text.toString().trim()
                val userId = userInput.text.toString().trim().ifBlank { null }
                if (serverUrl.isBlank() || tokenOrPin.isBlank()) {
                    error.text = getString(R.string.manual_pairing_required)
                    return@setPositiveButton
                }

                val pairing = if (tokenOrPin.length == 6 && tokenOrPin.all { it.isDigit() } && userId != null) {
                    QrPairing(serverUrl = serverUrl, pinCode = tokenOrPin, userId = userId)
                } else {
                    QrPairing(serverUrl = serverUrl, pairingToken = tokenOrPin)
                }
                showPairingConfirmation(pairing, null, progress, error)
            }
            .showKyDialog()
    }

    // ==========================================
    // 2. Lock Screen / Authentication Gate
    // ==========================================

    private fun renderLockScreen(root: LinearLayout, account: PairedAccount) {
        root.gravity = Gravity.CENTER

        root.addView(kyAuthWordmark(textSize = 34f, iconSizeDp = 64, centered = true))
        // The request is signed by the device key, never the vault key, so it needs no unlock.
        if (renderPendingChallenge(root, account)) {
            root.addView(secondaryButton(getString(R.string.unlock_biometrics)).apply {
                setOnClickListener { unlockWithPrompt() }
            }, fullWidthParams(top = 8))
            return
        }
        root.addView(TextView(this).apply {
            text = getString(R.string.vault_locked)
            textSize = 12f
            typeface = Typeface.MONOSPACE
            gravity = Gravity.CENTER
            letterSpacing = 0.18f
            setTextColor(ThemeManager.color(context, R.color.ky_cyan))
            setPadding(0, dp(4), 0, dp(24))
        })
        root.addView(TextView(this).apply {
            text = getString(R.string.unlock_your_vault)
            textSize = 24f
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER
            setTextColor(ThemeManager.color(context, R.color.ky_heading))
        })
        root.addView(TextView(this).apply {
            text = getString(R.string.paired_to, account.serverUrl)
            textSize = 15f
            gravity = Gravity.CENTER
            setTextColor(ThemeManager.color(context, R.color.ky_muted))
            setPadding(dp(16), dp(10), dp(16), dp(24))
        })

        fun lockActionParams(top: Int = 0) = fullWidthParams(top).apply {
            marginStart = dp(12)
            marginEnd = dp(12)
        }

        val error = message("").apply { setTextColor(ThemeManager.color(context, R.color.ky_error)) }
        val failureState = AppLockManager.getFailureState(this)
        val nowSec = System.currentTimeMillis() / 1000
        val retryWaitSec = PinFailurePolicy.secondsUntilRetry(failureState, nowSec)

        if (retryWaitSec > 0) {
            error.text = getString(R.string.pin_retry_wait, retryWaitSec)
        } else if (failureState.failedAttempts > 0) {
            val remaining = PinFailurePolicy.attemptsRemaining(failureState)
            error.text = getString(R.string.pin_attempts_remaining, remaining)
        }

        val btnBiometric = primaryButton(getString(R.string.unlock_biometrics)).apply {
            minHeight = dp(56)
            setOnClickListener {
                unlockWithPrompt(onError = { error.text = it })
            }
        }
        root.addView(btnBiometric, lockActionParams())

        if (AppLockManager.isPinEnabled(this) && AppLockManager.hasPinSet(this)) {
            val pinInput = EditText(this).apply {
                hint = "Enter PIN"
                inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
                gravity = Gravity.CENTER
                styleInput(this)
            }
            val btnPin = secondaryButton("Unlock with PIN").apply {
                setOnClickListener {
                    val pin = pinInput.text.toString()
                    unlockVault(
                        unlock = { AppLockManager.unlockWithPin(this@MainActivity, pin) },
                        onError = {
                            renderContent()
                            Toast.makeText(this@MainActivity, "Unable to unlock vault.", Toast.LENGTH_LONG).show()
                        },
                    )
                }
            }
            root.addView(pinInput, lockActionParams(top = 14))
            root.addView(btnPin, lockActionParams(top = 10))
        }

        root.addView(error.apply { gravity = Gravity.CENTER }, fullWidthParams(top = 8))
        root.addView(secondaryButton("About KyAuth").apply {
            setOnClickListener { showAboutDialog(this@MainActivity) }
        }, lockActionParams(top = 8))
        root.addView(ghostButton(getString(R.string.reset_kyauth)).apply {
            setTextColor(ThemeManager.color(context, R.color.ky_error))
            setOnClickListener { confirmReset() }
        }, lockActionParams(top = 8))
    }

    /** The way out of a vault that can no longer open. Five wrong PINs already allow the same wipe. */
    private fun confirmReset() {
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.reset_kyauth))
            .setMessage(getString(R.string.reset_kyauth_message))
            .setNegativeButton("Cancel", null)
            .setPositiveButton(getString(R.string.reset_kyauth_confirm)) { _, _ ->
                SecurityWipe.wipe(this)
                clearPendingChallenge()
                lockSensitiveState()
                renderContent()
            }
            .showKyDialog()
    }

    // ==========================================
    // 3. Main Dashboard & Tabs
    // ==========================================

    private fun renderDashboard(root: LinearLayout, account: PairedAccount) {
        val header = kyAuthWordmark(textSize = 32f, iconSizeDp = 56).apply {
            setPadding(0, dp(12), 0, dp(28))
        }
        root.addView(header, centeredWidthParams(maxWidthDp = dashboardMaxWidthDp()))

        val scroll = dashboardScroll()
        val container = dashboardContainer()
        scroll.addView(container, scrollContentParams())
        renderActiveTab(container, account)
        root.addView(scroll)
        root.addView(bottomNavigation(), navigationParams())
    }

    private fun dashboardScroll() = ScrollView(this).apply {
        isFillViewport = true
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            0,
            1f,
        ).apply { bottomMargin = dp(16) }
    }

    private fun dashboardContainer() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
    }

    private fun renderActiveTab(container: LinearLayout, account: PairedAccount) {
        when (activeTab) {
            Tab.VAULT -> renderTotpTab(container, account)
            Tab.SETTINGS -> renderSettingsTab(container, account)
        }
    }

    // ==========================================
    // Vault
    // ==========================================

    private fun renderTotpTab(container: LinearLayout, account: PairedAccount) {
        totpViews.clear()
        val headerRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            layoutParams = fullWidthParams(bottom = 16)
        }
        val headerTitle = TextView(this).apply {
            text = getString(R.string.tab_totp)
            textSize = 20f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ThemeManager.color(context, R.color.ky_heading))
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        val addButton = Button(this).apply {
            contentDescription = "Add TOTP account"
            minWidth = 0
            minHeight = 0
            stateListAnimator = null
            elevation = 0f
            setCompoundDrawablesWithIntrinsicBounds(0, R.drawable.ic_add, 0, 0)
            compoundDrawables[1]?.setTint(ThemeManager.color(context, R.color.ky_cyan))
            background = GradientDrawable().apply {
                setColor(ThemeManager.color(context, R.color.ky_surface_elevated))
                cornerRadius = dp(22).toFloat()
                setStroke(dp(1), ThemeManager.color(context, R.color.ky_border))
            }
            layoutParams = LinearLayout.LayoutParams(dp(44), dp(44))
            setOnClickListener { showAddTotpOptionsDialog() }
        }
        headerRow.addView(headerTitle)
        headerRow.addView(addButton)
        if (!demo) renderPushBanner(container, account)
        container.addView(headerRow)
        renderPendingChallenge(container, account)

        if (totpEntries.isEmpty()) {
            container.addView(emptyState("No codes yet", "Tap + to add an account or scan from Settings."))
            return
        }

        val nowSec = System.currentTimeMillis() / 1000
        val cards = mutableListOf<View>()
        for (entry in totpEntries) {
            val card = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                background = cardBackground()
                setPadding(dp(20), dp(18), dp(20), dp(18))
                layoutParams = fullWidthParams(bottom = 12)
            }

            val display = TotpDisplay.state(entry, nowSec, getString(R.string.totp_code_unavailable))

            val titleView = TextView(this).apply {
                text = entry.title
                textSize = 17f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(ThemeManager.color(context, R.color.ky_heading))
            }
            card.addView(titleView)

            entry.url?.let { url ->
                val urlView = TextView(this).apply {
                    text = url
                    textSize = 13f
                    setTextColor(ThemeManager.color(context, R.color.ky_cyan))
                    setPadding(0, dp(4), 0, 0)
                }
                card.addView(urlView)
            }

            val codeView = TextView(this).apply {
                text = display.formattedCode
                textSize = 34f
                typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
                setTextColor(ThemeManager.color(context, R.color.ky_cyan))
                setPadding(0, 8, 0, 8)
                setOnClickListener {
                    val current = TotpDisplay.state(entry, System.currentTimeMillis() / 1000, getString(R.string.totp_code_unavailable))
                    val code = current.code ?: return@setOnClickListener
                    val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    copyTotpCode(clipboard, code, current.remainingSeconds)
                    Toast.makeText(this@MainActivity, getString(R.string.copy_code), Toast.LENGTH_SHORT).show()
                }
            }
            val timerView = TextView(this).apply {
                text = getString(R.string.totp_expiry, display.remainingSeconds)
                textSize = 14f
                setTextColor(ThemeManager.color(context, R.color.ky_muted))
            }

            card.addView(codeView)
            card.addView(timerView)
            val progressView = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
                progressTintList = ColorStateList.valueOf(ThemeManager.color(context, R.color.ky_cyan))
                progressBackgroundTintList = ColorStateList.valueOf(ThemeManager.color(context, R.color.ky_border))
                max = entry.periodSeconds.toInt()
                progress = max(0, display.remainingSeconds.toInt())
            }
            card.addView(progressView, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(4)).apply { topMargin = dp(14) })
            totpViews.add(TotpViews(entry, codeView, timerView, progressView))

            entry.notes?.let { notes ->
                val notesView = TextView(this).apply {
                    text = notes
                    textSize = 13f
                    setTextColor(ThemeManager.color(context, R.color.ky_muted))
                    setPadding(0, dp(10), 0, 0)
                }
                card.addView(notesView)
            }

            card.setOnLongClickListener {
                showEditOrDeleteTotpDialog(entry)
                true
            }
            cards.add(card)
        }
        addAdaptiveCards(container, cards)
    }

    private fun updateTotpViews() {
        val now = System.currentTimeMillis() / 1000
        val unavailable = getString(R.string.totp_code_unavailable)
        totpViews.forEach { views ->
            val display = TotpDisplay.state(views.entry, now, unavailable)
            views.code.text = display.formattedCode
            views.timer.text = getString(R.string.totp_expiry, display.remainingSeconds)
            views.progress.progress = max(0, display.remainingSeconds.toInt())
        }
    }

    private fun showAddTotpOptionsDialog() {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(20))
        }
        val titleView = TextView(this).apply {
            text = getString(R.string.add_to_totp_vault)
            textSize = 20f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ThemeManager.color(context, R.color.ky_heading))
            setPadding(0, 0, 0, dp(4))
        }
        val messageView = TextView(this).apply {
            text = getString(R.string.add_totp_choice)
            textSize = 14f
            setTextColor(ThemeManager.color(context, R.color.ky_muted))
            setPadding(0, 0, 0, dp(18))
        }
        container.addView(titleView)
        container.addView(messageView)

        var dialog: AlertDialog? = null

        val btnScan = primaryButton("Scan QR Code").apply {
            setOnClickListener {
                dialog?.dismiss()
                scanTotpQr()
            }
        }
        val btnManual = secondaryButton("Add Manually").apply {
            setOnClickListener {
                dialog?.dismiss()
                showAddTotpDialog()
            }
        }
        val btnCancel = ghostButton("Cancel").apply {
            setOnClickListener { dialog?.dismiss() }
        }

        container.addView(btnScan, fullWidthParams(bottom = 10))
        container.addView(btnManual, fullWidthParams(bottom = 6))
        container.addView(btnCancel, fullWidthParams())

        dialog = AlertDialog.Builder(this)
            .setView(container)
            .showKyDialog()
    }

    private fun scanTotpQr() = qrScanner.scan(ScanPurpose.TOTP)

    /**
     * A scan result can arrive in an activity recreated while the scanner was open, before
     * onResume has loaded the vault or rendered a screen. Until then it is only stashed: adding a
     * TOTP entry to the not-yet-loaded list and saving would overwrite the vault.
     */
    private fun onQrScanned(purpose: ScanPurpose, text: String?) {
        val resumed = lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED)
        when (purpose) {
            ScanPurpose.PAIRING -> {
                scannedPairing = text?.let { Result.success(it) } ?: Result.failure(IllegalStateException())
                if (resumed) renderContent() // else onResume renders and the enrollment screen consumes it
            }
            ScanPurpose.TOTP -> {
                if (text == null) return
                val entry = runCatching { TotpUriParser.parse(text) }.getOrElse {
                    Toast.makeText(this, "Invalid OTP QR code", Toast.LENGTH_SHORT).show()
                    return
                }
                if (resumed) queueTotpEntry(entry) else pendingTotpEntry = entry // loadTotpEntries adds it
            }
        }
    }

    private fun showAddTotpDialog() {
        val form = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(20))
        }
        val titleView = TextView(this).apply {
            text = getString(R.string.add_manually)
            textSize = 20f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ThemeManager.color(context, R.color.ky_heading))
            setPadding(0, 0, 0, dp(4))
        }
        val subtitleView = TextView(this).apply {
            text = getString(R.string.add_totp_description)
            textSize = 14f
            setTextColor(ThemeManager.color(context, R.color.ky_muted))
            setPadding(0, 0, 0, dp(16))
        }
        form.addView(titleView)
        form.addView(subtitleView)

        val titleInput = EditText(this).apply { hint = "Account Name (e.g. GitHub)"; styleInput(this) }
        val secretInput = EditText(this).apply { hint = "Secret Key (Base32)"; styleInput(this) }
        val urlInput = EditText(this).apply { hint = "Website (URL) (optional)"; styleInput(this) }
        val notesInput = EditText(this).apply {
            hint = "Notes (optional)"
            minLines = 3
            gravity = Gravity.TOP
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES or InputType.TYPE_TEXT_FLAG_MULTI_LINE
            styleInput(this)
        }
        form.addView(titleInput, fullWidthParams(bottom = 10))
        form.addView(secretInput, fullWidthParams(bottom = 10))
        form.addView(urlInput, fullWidthParams(bottom = 10))
        form.addView(notesInput, fullWidthParams(bottom = 18))

        var dialog: AlertDialog? = null

        val actions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.END
        }
        val btnCancel = ghostButton("Cancel").apply {
            setOnClickListener { dialog?.dismiss() }
        }
        val btnSave = primaryButton("Save").apply {
            setPadding(dp(24), 0, dp(24), 0)
            setOnClickListener {
                val title = titleInput.text.toString().trim()
                val secret = secretInput.text.toString().trim().replace(" ", "")
                val url = urlInput.text.toString().trim().ifBlank { null }
                val notes = notesInput.text.toString().trim().ifBlank { null }
                if (title.isNotBlank() && secret.isNotBlank()) {
                    runCatching {
                        TotpEntry(
                            title = title,
                            secretBase32 = secret,
                            url = url,
                            notes = notes,
                        )
                    }.onSuccess {
                        addTotpEntry(it)
                        dialog?.dismiss()
                    }.onFailure {
                        Toast.makeText(this@MainActivity, it.message ?: "Invalid secret", Toast.LENGTH_SHORT).show()
                    }
                } else {
                    Toast.makeText(this@MainActivity, "Account name and secret key are required", Toast.LENGTH_SHORT).show()
                }
            }
        }
        actions.addView(btnCancel)
        actions.addView(btnSave, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginStart = dp(8) })
        form.addView(actions)

        val scrollView = ScrollView(this).apply {
            clipToPadding = false
            addView(form)
        }

        dialog = AlertDialog.Builder(this)
            .setView(scrollView)
            .showKyDialog()
    }

    private fun showEditTotpDialog(entry: TotpEntry) {
        val form = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(20))
        }
        val titleView = TextView(this).apply {
            text = getString(R.string.edit_account)
            textSize = 20f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ThemeManager.color(context, R.color.ky_heading))
            setPadding(0, 0, 0, dp(4))
        }
        val subtitleView = TextView(this).apply {
            text = entry.title
            textSize = 14f
            setTextColor(ThemeManager.color(context, R.color.ky_muted))
            setPadding(0, 0, 0, dp(16))
        }
        form.addView(titleView)
        form.addView(subtitleView)

        val titleInput = EditText(this).apply {
            hint = "Account Name (e.g. GitHub)"
            setText(entry.title)
            styleInput(this)
        }
        val secretInput = EditText(this).apply {
            hint = "Secret Key (Base32)"
            setText(entry.secretBase32)
            styleInput(this)
        }
        val urlInput = EditText(this).apply {
            hint = "Website (URL) (optional)"
            setText(entry.url.orEmpty())
            styleInput(this)
        }
        val notesInput = EditText(this).apply {
            hint = "Notes (optional)"
            minLines = 3
            gravity = Gravity.TOP
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES or InputType.TYPE_TEXT_FLAG_MULTI_LINE
            setText(entry.notes.orEmpty())
            styleInput(this)
        }
        form.addView(titleInput, fullWidthParams(bottom = 10))
        form.addView(secretInput, fullWidthParams(bottom = 10))
        form.addView(urlInput, fullWidthParams(bottom = 10))
        form.addView(notesInput, fullWidthParams(bottom = 18))

        var dialog: AlertDialog? = null

        val actions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.END
        }
        val btnCancel = ghostButton("Cancel").apply {
            setOnClickListener { dialog?.dismiss() }
        }
        val btnSave = primaryButton("Save").apply {
            setPadding(dp(24), 0, dp(24), 0)
            setOnClickListener {
                val title = titleInput.text.toString().trim()
                val secret = secretInput.text.toString().trim().replace(" ", "")
                val url = urlInput.text.toString().trim().ifBlank { null }
                val notes = notesInput.text.toString().trim().ifBlank { null }
                if (title.isNotBlank() && secret.isNotBlank()) {
                    runCatching {
                        entry.copy(
                            title = title,
                            secretBase32 = secret,
                            url = url,
                            notes = notes,
                        )
                    }.onSuccess { updated ->
                        val idx = totpEntries.indexOfFirst { it.id == entry.id }
                        if (idx >= 0) {
                            totpEntries[idx] = updated
                        } else {
                            totpEntries.add(updated)
                        }
                        saveTotpEntries()
                        renderContent()
                        dialog?.dismiss()
                    }.onFailure {
                        Toast.makeText(this@MainActivity, it.message ?: "Invalid entry", Toast.LENGTH_SHORT).show()
                    }
                } else {
                    Toast.makeText(this@MainActivity, "Account name and secret key are required", Toast.LENGTH_SHORT).show()
                }
            }
        }
        actions.addView(btnCancel)
        actions.addView(btnSave, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginStart = dp(8) })
        form.addView(actions)

        val scrollView = ScrollView(this).apply {
            clipToPadding = false
            addView(form)
        }

        dialog = AlertDialog.Builder(this)
            .setView(scrollView)
            .showKyDialog()
    }

    private fun showEditOrDeleteTotpDialog(entry: TotpEntry) {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(20))
        }
        val titleView = TextView(this).apply {
            text = entry.title
            textSize = 20f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ThemeManager.color(context, R.color.ky_heading))
            setPadding(0, 0, 0, dp(4))
        }
        container.addView(titleView)

        entry.url?.let { url ->
            val urlView = TextView(this).apply {
                text = url
                textSize = 13f
                setTextColor(ThemeManager.color(context, R.color.ky_cyan))
                setPadding(0, 0, 0, dp(4))
            }
            container.addView(urlView)
        }

        entry.notes?.let { notes ->
            val notesView = TextView(this).apply {
                text = notes
                textSize = 13f
                setTextColor(ThemeManager.color(context, R.color.ky_muted))
                setPadding(0, dp(4), 0, dp(8))
            }
            container.addView(notesView)
        }

        var dialog: AlertDialog? = null

        val btnEdit = secondaryButton("Edit Entry").apply {
            setOnClickListener {
                dialog?.dismiss()
                showEditTotpDialog(entry)
            }
        }
        val btnDelete = secondaryButton("Delete Entry").apply {
            setTextColor(ThemeManager.color(context, R.color.ky_error))
            setOnClickListener {
                dialog?.dismiss()
                totpEntries.removeAll { it.id == entry.id }
                saveTotpEntries()
                renderContent()
            }
        }
        val btnCancel = ghostButton("Cancel").apply {
            setOnClickListener { dialog?.dismiss() }
        }

        container.addView(btnEdit, fullWidthParams(top = 10, bottom = 10))
        container.addView(btnDelete, fullWidthParams(bottom = 6))
        container.addView(btnCancel, fullWidthParams())

        dialog = AlertDialog.Builder(this)
            .setView(container)
            .showKyDialog()
    }

    private fun loadTotpEntries() {
        if (demo) return
        val vaultKey = AppLockManager.getVaultKey() ?: return
        totpEntries = TotpVault.load(vaultFile, vaultKey).toMutableList()
        vaultLoaded = true
        pendingTotpEntry?.let {
            pendingTotpEntry = null
            totpEntries.add(it)
            saveTotpEntries()
        }
    }

    private fun saveTotpEntries() {
        if (demo) return
        val vaultKey = AppLockManager.getVaultKey()
        if (vaultKey == null || !vaultLoaded) {
            toast("TOTP vault is not open. The change was not saved.")
            return
        }
        TotpVault.save(vaultFile, vaultKey, totpEntries)
    }

    private fun addTotpEntry(entry: TotpEntry) {
        totpEntries.add(entry)
        saveTotpEntries()
        renderContent()
    }

    private fun queueTotpEntry(entry: TotpEntry) {
        if (AppLockManager.isUnlocked() || demo) {
            addTotpEntry(entry)
        } else {
            pendingTotpEntry = entry
            Toast.makeText(this, "Unlock to save the scanned TOTP entry.", Toast.LENGTH_SHORT).show()
            renderContent()
        }
    }

    /**
     * The pending Push MFA request: at the top of Vault, or alone on the lock screen. Adds nothing
     * and returns false when none is live.
     */
    private fun renderPendingChallenge(container: LinearLayout, account: PairedAccount): Boolean {
        val challenge = pendingChallenge ?: return false
        val challengeStore = MfaPushChallengeStore(this)
        if (challengeStore.isExpired(challenge)) {
            pendingChallenge = null
            if (demo) nextDemoPushAt = android.os.SystemClock.elapsedRealtime() + DemoMode.PUSH_INTERVAL_MS else challengeStore.clear()
            return false
        }

        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = cardBackground()
            setPadding(dp(20), dp(20), dp(20), dp(20))
        }
        card.addView(title(if (challenge.purpose == "step_up") "Confirm a sensitive action" else "Sign-in request"))
        card.addView(message("A request was received for:\n${challenge.serverUrl}\nUser: ${challenge.username ?: account.deviceName}\nExpires in ${challengeStore.secondsRemaining(challenge)} seconds.\n\nEnter the 2-digit number shown on your computer screen:"))
        if (demo) card.addView(message(getString(R.string.demo_push_hint, challenge.matchDigits)))
        val digits = EditText(this).apply {
            hint = "00"
            inputType = InputType.TYPE_CLASS_NUMBER
            filters = arrayOf(InputFilter.LengthFilter(2))
            imeOptions = EditorInfo.IME_ACTION_DONE or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
            setSingleLine(true)
            gravity = Gravity.CENTER
            textSize = 24f
        }
        val approve = {
            val selected = digits.text.toString().trim()
            if (demo) answerDemoChallenge(challenge, approve = true, selected) else respondToChallenge(challenge, account, approve = true, selected)
        }
        digits.setOnEditorActionListener { _, actionId, _ ->
            (actionId == EditorInfo.IME_ACTION_DONE).also { if (it) approve() }
        }
        card.addView(digits)
        card.addView(primaryButton("Approve request").apply {
            layoutParams = fullWidthParams(bottom = 8)
            setOnClickListener { approve() }
        })

        val btnDeny = secondaryButton("Deny request").apply {
            layoutParams = fullWidthParams(bottom = 8)
            setTextColor(ThemeManager.color(context, R.color.ky_error))
            setOnClickListener { if (demo) answerDemoChallenge(challenge, approve = false, "") else respondToChallenge(challenge, account, approve = false, "") }
        }
        card.addView(btnDeny)
        container.addView(card, fullWidthParams(bottom = 16))
        if (digits.requestFocus()) {
            digits.post { getSystemService(InputMethodManager::class.java).showSoftInput(digits, 0) }
        }
        return true
    }

    private fun startDemo() {
        lockSensitiveState()
        pendingChallenge = null
        demo = true
        activeTab = Tab.VAULT
        nextDemoPushAt = android.os.SystemClock.elapsedRealtime() + 3_000
        renderContent()
    }

    private fun exitDemo() {
        demo = false
        pendingChallenge = null
        lockSensitiveState()
        renderContent()
        prepareUnifiedPushForPairing()
    }

    /** Raises a fake sign-in request while the demo is on screen. */
    private fun simulateDemoPush() {
        if (!demo || pendingChallenge != null || !lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED)) return
        if (android.os.SystemClock.elapsedRealtime() < nextDemoPushAt) return
        pendingChallenge = DemoMode.challenge(System.currentTimeMillis())
        Toast.makeText(this, getString(R.string.demo_push_received), Toast.LENGTH_SHORT).show()
        renderContent()
    }

    private fun answerDemoChallenge(challenge: MfaChallenge, approve: Boolean, selectedDigit: String) {
        val result = when {
            MfaPushChallengeStore(this).isExpired(challenge) -> "Sign-in request expired"
            !approve -> "Sign-in Denied"
            selectedDigit == challenge.matchDigits -> "Sign-in Approved"
            else -> "Wrong number. Sign-in Denied"
        }
        pendingChallenge = null
        nextDemoPushAt = android.os.SystemClock.elapsedRealtime() + DemoMode.PUSH_INTERVAL_MS
        Toast.makeText(this, result, Toast.LENGTH_SHORT).show()
        renderContent()
    }

    private fun renderPushBanner(container: LinearLayout, account: PairedAccount) {
        val push = PushStore(this)
        val broken = push.broken()
        if (!push.refreshPending() && broken == null) return
        val banner = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = cardBackground()
            setPadding(dp(20), dp(16), dp(20), dp(16))
        }
        banner.addView(message(listOfNotNull("Sign-in requests paused", broken).joinToString("\n")))
        banner.addView(primaryButton("Reconnect").apply {
            setOnClickListener { reconnectPush(account) }
        }, fullWidthParams())
        container.addView(banner, fullWidthParams(bottom = 16))
    }

    private fun reconnectPush(account: PairedAccount) {
        val push = PushStore(this)
        if (push.transport == PushCredential.UNIFIED_PUSH) {
            val credential = push.unifiedPushCredential()
            if (credential != null) {
                refreshPush(account, credential)
            } else {
                registerUnifiedPush { toast(it ?: getString(R.string.push_waiting_for_distributor)) }
            }
            return
        }
        Thread {
            val credential = ChannelPush.fcmCredential()
            runOnUiThread {
                credential.onSuccess { refreshPush(account, it) }
                    .onFailure { toast(it.message ?: "Firebase is unavailable") }
            }
        }.start()
    }

    /** One prompt signs the refresh; the registered credential changes only after KyIdentity's 2xx. */
    private fun refreshPush(account: PairedAccount, credential: PushCredential) {
        val issuedAt = System.currentTimeMillis()
        val message = runCatching { PushRefreshClient.message(account.serverUrl, account.deviceId, issuedAt, credential) }
            .getOrElse { return toast("This pairing cannot reconnect. Pair KyAuth again.") }
        val signature = runCatching { DeviceSigningKey.initSignature() }
            .getOrElse { return toast("Unable to use the device key. Pair KyAuth again.") }
        VaultUnlockPrompt.showForSignature(this, "Reconnect sign-in requests", signature, onAuthenticated = { authenticated ->
            val signed = runCatching { DeviceSigningKey.sign(message, authenticated) }
                .getOrElse { return@showForSignature toast("Unable to use the device key. Pair KyAuth again.") }
            Thread {
                val result = PushRefreshClient().refresh(account.serverUrl, account.deviceId, credential, issuedAt, signed)
                runOnUiThread {
                    result.onSuccess {
                        val push = PushStore(this)
                        push.markRegistered(credential)
                        // KyIdentity now pushes over UnifiedPush, so the FCM token has no use left.
                        if (credential.transport == PushCredential.UNIFIED_PUSH) {
                            ChannelPush.forget()
                            push.forgetFcm()
                        }
                        toast("Sign-in requests reconnected")
                    }.onFailure { toast(it.message ?: "Reconnecting failed") }
                    renderContent()
                }
            }.start()
        }, onFailed = { toast("Unlock required: $it") })
    }

    private fun registerUnifiedPush(onResult: (String?) -> Unit) =
        UnifiedPushRegistrar.register(this, { it.showKyDialog() }, onResult)

    private fun toast(text: String) = Toast.makeText(this, text, Toast.LENGTH_LONG).show()

    /** Signs and sends one answer. The device key's own prompt is the only authentication. */
    private fun respondToChallenge(challenge: MfaChallenge, account: PairedAccount, approve: Boolean, digits: String) {
        // A mistyped number would be a denial at the server, so it never reaches the prompt.
        if (approve && !TWO_DIGITS.matches(digits)) {
            Toast.makeText(this, "Enter the 2-digit number shown on your computer screen.", Toast.LENGTH_SHORT).show()
            return
        }
        // Answers go to the current pairing only, and only while the request is still stored:
        // one answered from another activity instance, or left from an earlier pairing, is dropped.
        val challengeStore = MfaPushChallengeStore(this)
        if (challenge.serverUrl.trim() != account.serverUrl.trim()) challengeStore.clear(challenge.challengeId)
        val stored = challengeStore.load()
        if (stored?.challengeId != challenge.challengeId) {
            pendingChallenge = stored // whatever is still open, possibly a newer request
            renderContent()
            return
        }
        val payload = runCatching {
            MfaMessage.formatPayload(
                MfaMessage.origin(account.serverUrl), requireNotNull(account.userId), account.deviceId,
                challenge.challengeId, challenge.purpose, challenge.expiresAtEpochMs, approve, digits,
            )
        }.getOrElse {
            Toast.makeText(this, "This pairing cannot answer the request. Pair KyAuth again.", Toast.LENGTH_LONG).show()
            return
        }
        val unauthorized = "Unable to authorize this request. Use your fingerprint or re-pair KyAuth."
        val sig = runCatching { DeviceSigningKey.initSignature() }.getOrElse {
            Toast.makeText(this, unauthorized, Toast.LENGTH_LONG).show()
            return
        }
        VaultUnlockPrompt.showForSignature(
            this,
            if (approve) "Approve sign-in match $digits" else "Deny sign-in request",
            sig,
            onAuthenticated = { authedSig ->
                val signature = runCatching { DeviceSigningKey.sign(payload, authedSig) }.getOrElse {
                    Toast.makeText(this, unauthorized, Toast.LENGTH_LONG).show()
                    return@showForSignature
                }
                Thread {
                    val result = MfaResponseClient().respond(
                        serverUrl = account.serverUrl,
                        challengeId = challenge.challengeId,
                        deviceId = account.deviceId,
                        selectedDigits = digits,
                        approve = approve,
                        signature = signature,
                    )
                    // Before the UI hop: an activity recreated mid-request must not see the request as open.
                    if (result is MfaResponseResult.Success) MfaPushChallengeStore(applicationContext).clear(challenge.challengeId)
                    runOnUiThread {
                        if (isDestroyed) return@runOnUiThread
                        when (result) {
                            is MfaResponseResult.Success -> onAnswerAccepted(result.approved)
                            is MfaResponseResult.Error -> {
                                Toast.makeText(this, result.message, Toast.LENGTH_LONG).show()
                                renderContent()
                            }
                        }
                    }
                }.start()
            },
            onFailed = { Toast.makeText(this, "Unlock required: $it", Toast.LENGTH_SHORT).show() },
        )
    }

    // ==========================================
    // Settings & Security
    // ==========================================

    private fun renderSettingsTab(container: LinearLayout, account: PairedAccount) {
        val sections = mutableListOf<View>()

        val appearanceSection = settingsCard()
        appearanceSection.addView(title("Appearance"))
        appearanceSection.addView(message("Theme: ${ThemeManager.currentName(this)}"))
        appearanceSection.addView(secondaryButton("Select theme").apply {
            setOnClickListener { showThemePicker() }
        }, fullWidthParams())
        sections.add(appearanceSection)

        if (demo) {
            val demoSection = settingsCard()
            demoSection.addView(title(getString(R.string.demo_title)))
            demoSection.addView(message(getString(R.string.demo_settings_message)))
            demoSection.addView(primaryButton(getString(R.string.demo_exit)).apply {
                setOnClickListener { exitDemo() }
            }, fullWidthParams())
            sections.add(demoSection)
            sections.add(aboutSection())
            addAdaptiveCards(container, sections)
            return
        }

        val accountSection = settingsCard()
        accountSection.addView(title("Paired Account"))
        accountSection.addView(message("Server: ${account.serverUrl}\nDevice ID: ${account.deviceId}\nDevice Name: ${account.deviceName}\nUser ID: ${account.userId ?: "N/A"}"))

        val systemAccount = KyIdentityAccount.current(this)
        val signOnState = when {
            !account.canSignOn -> "Suite app sign-in: off for this device (enable it on the KyIdentity devices page, then pair again)"
            systemAccount != null -> "Suite app sign-in: on. KyPost and other suite apps can use this account."
            else -> "Suite app sign-in: account missing"
        }
        accountSection.addView(message(signOnState))
        accountSection.addView(message(attestationSummary(account.attestedLevel, account.bootState, account.attestationReason, ::getString)))
        if (account.canSignOn && systemAccount == null) {
            accountSection.addView(secondaryButton("Restore system account").apply {
                setOnClickListener {
                    val ok = runCatching { KyIdentityAccount.sync(this@MainActivity, account) }.getOrDefault(false)
                    if (!ok) Toast.makeText(this@MainActivity, "Could not restore the system account", Toast.LENGTH_LONG).show()
                    renderContent()
                }
            }, fullWidthParams())
        }

        val btnUnpair = secondaryButton(getString(R.string.unpair_account)).apply {
            setTextColor(ThemeManager.color(context, R.color.ky_error))
            setOnClickListener {
                AlertDialog.Builder(this@MainActivity)
                    .setTitle("Unpair Device")
                    .setMessage("Are you sure you want to unpair this device from KyIdentity?")
                    .setNegativeButton("Cancel", null)
                    .setPositiveButton("Unpair") { _, _ -> unpairIdentity(account) }
                    .showKyDialog()
            }
        }
        accountSection.addView(btnUnpair, fullWidthParams())
        sections.add(accountSection)

        sections.add(pushDeliverySection())

        val securitySection = settingsCard()
        securitySection.addView(title("Security & App Lock"))
        val pinSwitch = Switch(this).apply {
            text = getString(R.string.enable_pin)
            isChecked = AppLockManager.isPinEnabled(this@MainActivity)
            setTextColor(ThemeManager.color(context, R.color.ky_text))
            setOnCheckedChangeListener { _, isChecked ->
                if (isChecked && !AppLockManager.hasPinSet(this@MainActivity)) {
                    showSetPinDialog()
                } else {
                    AppLockManager.setPinEnabled(this@MainActivity, isChecked)
                }
            }
        }
        securitySection.addView(secondaryButton("Auto-lock after ${idleMinutes()} minutes").apply {
            setOnClickListener {
                AlertDialog.Builder(this@MainActivity).setTitle("Auto-lock when inactive")
                    .setItems(IdleLock.minutes.map { "$it minutes" }.toTypedArray()) { _, index ->
                        idlePreferences.edit().putInt("idle_lock_minutes", IdleLock.minutes[index]).apply()
                        AppLockManager.idleLock.reset()
                        renderContent()
                    }.showKyDialog()
            }
        }, fullWidthParams(bottom = 8))
        securitySection.addView(pinSwitch)

        val btnChangePin = secondaryButton(getString(R.string.change_pin)).apply {
            setOnClickListener { showSetPinDialog() }
        }
        securitySection.addView(btnChangePin, fullWidthParams())

        securitySection.addView(message("Auto-wipe policy: After 5 consecutive failed PIN attempts, all vault keys, accounts, and pairing data will be automatically wiped."))
        sections.add(securitySection)

        sections.add(aboutSection())

        addAdaptiveCards(container, sections)
    }

    private fun aboutSection() = settingsCard().apply {
        addView(title("About"))
        addView(message("KyAuth v${BuildConfig.VERSION_NAME}"))
        addView(secondaryButton("About KyAuth").apply {
            setOnClickListener { showAboutDialog(this@MainActivity) }
        }, fullWidthParams())
    }

    private fun pushDeliverySection(): View {
        val push = PushStore(this)
        val section = settingsCard()
        section.addView(title("Sign-in request delivery"))
        val unifiedPush = push.transport == PushCredential.UNIFIED_PUSH
        val status = when {
            !unifiedPush -> "Firebase"
            push.broken() != null -> "UnifiedPush: ${push.broken()}"
            push.unifiedPushCredential() == null -> "UnifiedPush: waiting for a distributor"
            else -> "UnifiedPush via ${UnifiedPushRegistrar.distributor(this) ?: "unknown distributor"}"
        }
        section.addView(message(if (push.refreshPending()) "$status\nPaused until you reconnect on the Vault tab." else status))
        if (unifiedPush) {
            section.addView(secondaryButton("Choose distributor").apply {
                setOnClickListener { UnifiedPushRegistrar.pick(this@MainActivity) { it?.let(::toast); renderContent() } }
            }, fullWidthParams(bottom = 8))
        }
        if (BuildConfig.HAS_FCM) {
            section.addView(secondaryButton(if (unifiedPush) "Use Firebase" else "Use UnifiedPush").apply {
                setOnClickListener { if (unifiedPush) selectFirebase() else selectUnifiedPush() }
            }, fullWidthParams())
        }
        return section
    }

    private fun selectUnifiedPush() = registerUnifiedPush { failure ->
        if (failure != null) return@registerUnifiedPush toast(failure)
        val push = PushStore(this)
        push.transport = PushCredential.UNIFIED_PUSH
        if (push.registered()?.transport != PushCredential.UNIFIED_PUSH) push.markRefreshPending()
        renderContent()
    }

    private fun selectFirebase() {
        val push = PushStore(this)
        push.transport = PushCredential.FCM
        UnifiedPushRegistrar.unregister(this)
        push.forgetUnifiedPush() // the connector reports no onUnregistered for an explicit unregister
        if (push.registered()?.transport != PushCredential.FCM) push.markRefreshPending()
        renderContent()
    }

    private fun showSetPinDialog() {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 24)
        }
        val pinInput = EditText(this).apply {
            hint = "New PIN (${PinPolicy.MIN_LENGTH}-${PinPolicy.MAX_LENGTH} digits)"
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
            styleInput(this)
        }
        container.addView(pinInput)

        AlertDialog.Builder(this)
            .setTitle(getString(R.string.change_pin))
            .setView(container)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Set PIN") { _, _ ->
                val pin = pinInput.text.toString().trim()
                val validation = PinPolicy.validate(pin)
                if (validation is PinPolicy.ValidationResult.Valid) {
                    runCatching { AppLockManager.setupPin(this, pin) }
                        .onSuccess { Toast.makeText(this, "PIN saved successfully", Toast.LENGTH_SHORT).show() }
                        .onFailure { Toast.makeText(this, "PIN not saved: ${it.message}", Toast.LENGTH_LONG).show() }
                    renderContent()
                } else {
                    Toast.makeText(this, (validation as PinPolicy.ValidationResult.Error).message, Toast.LENGTH_LONG).show()
                }
            }
            .showKyDialog()
    }

    private fun showThemePicker() {
        val names = ThemeManager.names()
        val current = ThemeManager.currentName(this)
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(20))
        }
        val titleView = TextView(this).apply {
            text = getString(R.string.select_theme)
            textSize = 20f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ThemeManager.color(context, R.color.ky_heading))
            setPadding(0, 0, 0, dp(16))
        }
        container.addView(titleView)

        val listContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        var dialog: AlertDialog? = null

        names.forEach { name ->
            val isSelected = name == current
            val itemBtn = Button(this).apply {
                text = if (isSelected) "$name  ✓" else name
                transformationMethod = null
                textSize = 15f
                typeface = if (isSelected) Typeface.DEFAULT_BOLD else Typeface.DEFAULT
                gravity = Gravity.START or Gravity.CENTER_VERTICAL
                setPadding(dp(16), dp(12), dp(16), dp(12))
                minHeight = dp(44)
                stateListAnimator = null
                elevation = 0f
                setTextColor(ThemeManager.color(context, if (isSelected) R.color.ky_cyan else R.color.ky_text))
                background = GradientDrawable().apply {
                    setColor(ThemeManager.color(context, if (isSelected) R.color.ky_surface_elevated else R.color.ky_surface))
                    cornerRadius = dp(12).toFloat()
                    if (isSelected) {
                        setStroke(dp(1), ThemeManager.color(context, R.color.ky_cyan))
                    }
                }
                setOnClickListener {
                    ThemeManager.set(this@MainActivity, name)
                    dialog?.dismiss()
                    renderContent()
                }
            }
            listContainer.addView(itemBtn, fullWidthParams(bottom = 6))
        }

        val scrollView = ScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                (resources.displayMetrics.heightPixels * 0.45f).toInt(),
            )
            addView(listContainer)
        }
        container.addView(scrollView)

        val btnCancel = ghostButton("Cancel").apply {
            setOnClickListener { dialog?.dismiss() }
        }
        container.addView(btnCancel, fullWidthParams(top = 10))

        dialog = AlertDialog.Builder(this)
            .setView(container)
            .showKyDialog()
    }

    // ==========================================
    // Biometric Authentication Helper
    // ==========================================

    private fun unlockVault(unlock: () -> Boolean, onError: () -> Unit) {
        if (isVaultLoading) return
        val generation = AppLockManager.lockGeneration
        vaultLoadGeneration = generation
        isVaultLoading = true
        renderVaultUnlocking()
        Thread {
            val result = runCatching {
                synchronized(AppLockManager) {
                    check(generation == AppLockManager.lockGeneration)
                    check(unlock())
                }
                val totpKey = checkNotNull(AppLockManager.getVaultKey())
                TotpVault.load(vaultFile, totpKey)
            }
            runOnUiThread {
                if (vaultLoadGeneration != generation) return@runOnUiThread
                vaultLoadGeneration = null
                isVaultLoading = false
                if (generation != AppLockManager.lockGeneration) {
                    renderContent()
                    return@runOnUiThread
                }
                if (!AppLockManager.isUnlocked()) {
                    onError()
                    return@runOnUiThread
                }
                result.onSuccess { totp ->
                    totpEntries = totp.toMutableList()
                    vaultLoaded = true
                    pendingTotpEntry?.let { entry ->
                        pendingTotpEntry = null
                        runCatching { addTotpEntry(entry) }.onFailure {
                            Toast.makeText(this, "Could not save scanned account", Toast.LENGTH_LONG).show()
                        }
                    }
                    renderContent()
                }.onFailure {
                    lockSensitiveState()
                    if (it is TotpVaultException) {
                        renderContent()
                        toast(VAULT_UNREADABLE)
                    } else {
                        onError()
                    }
                }
            }
        }.start()
    }

    private fun renderVaultUnlocking() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setBackgroundColor(ThemeManager.color(context, R.color.ky_background))
        }
        applyRootPadding(root)
        root.addView(ProgressBar(this))
        root.addView(message("Unlocking vault…"), LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.WRAP_CONTENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = dp(16) })
        setRootContentView(root)
    }

    /**
     * Unlocks the vault. The cipher comes from the prompt itself, so nothing is decrypted unless
     * the framework reports a successful authentication.
     */
    private fun unlockWithPrompt(
        reason: String = "Unlock KyAuth",
        silent: Boolean = false,
        onError: (String) -> Unit = {},
    ) {
        if (silent && !VaultUnlockPrompt.canAuthenticate(this)) return
        val generation = AppLockManager.lockGeneration
        VaultUnlockPrompt.show(
            activity = this,
            subtitle = reason,
            onAuthenticated = { cipher ->
                if (isDestroyed || generation != AppLockManager.lockGeneration) return@show
                unlockVault(
                    unlock = { AppLockManager.unlockWithBiometrics(this, cipher, vaultFile.exists()) },
                    onError = {
                        renderContent()
                        Toast.makeText(this, "Unlock failed. Use your PIN, or reset KyAuth.", Toast.LENGTH_LONG).show()
                    },
                )
            },
            onFailed = { if (!silent) onError("Unlock required: $it") },
        )
    }

    private fun authenticateWithBiometrics(
        reason: String = "Unlock KyAuth",
        silent: Boolean = false,
        onSuccess: () -> Unit = {},
        onError: (String) -> Unit = {},
    ) {
        val generation = AppLockManager.lockGeneration
        val biometricManager = BiometricManager.from(this)
        val canAuthenticate = biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL,
        )

        if (canAuthenticate != BiometricManager.BIOMETRIC_SUCCESS && silent) {
            return
        }

        BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                if (!isDestroyed && generation == AppLockManager.lockGeneration) onSuccess()
            }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (!silent) onError("Unlock required: $errString")
            }
        }).authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("KyAuth")
                .setSubtitle(reason)
                .setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                )
                .build(),
        )
    }

    private fun loadPendingPushChallenge() {
        MfaPushChallengeStore(this).load()?.let {
            pendingChallenge = it
            activeTab = Tab.VAULT
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU || store.account() == null) return
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) return
        ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1001)
    }

    private fun applyRootPadding(root: View) {
        val horizontal = dp(screenEdgePaddingDp())
        root.setPadding(
            horizontal,
            dp(12) + systemBarFallbackHeight("status_bar_height"),
            horizontal,
            dp(16) + systemBarFallbackHeight("navigation_bar_height"),
        )
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(horizontal, dp(12) + bars.top, horizontal, dp(16) + bars.bottom)
            insets
        }
    }

    private fun setRootContentView(root: View) {
        setContentView(root)
        val background = ThemeManager.color(this, R.color.ky_background)
        window.statusBarColor = background
        window.navigationBarColor = background
        val lightBackground = androidx.core.graphics.ColorUtils.calculateLuminance(background) > 0.5
        androidx.core.view.WindowCompat.getInsetsController(window, root).apply {
            isAppearanceLightStatusBars = lightBackground
            isAppearanceLightNavigationBars = lightBackground
        }
        ViewCompat.requestApplyInsets(root)
    }

    private fun systemBarFallbackHeight(name: String): Int {
        val id = resources.getIdentifier(name, "dimen", "android")
        return if (id > 0) resources.getDimensionPixelSize(id) else 0
    }

    private fun screenEdgePaddingDp() = when {
        isExpandedWidth() -> 40
        isCompactWidth() -> 20
        else -> 28
    }

    private fun brand(title: String, subtitle: String): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.CENTER_HORIZONTAL
        setPadding(0, dp(40), 0, dp(40))
        addView(kyAuthWordmark(title, textSize = 28f, iconSizeDp = 48, centered = true))
        addView(TextView(context).apply {
            text = subtitle
            textSize = 12f
            typeface = Typeface.MONOSPACE
            setTextColor(ThemeManager.color(context, R.color.ky_cyan))
            gravity = Gravity.CENTER
            letterSpacing = 0.2f
        })
    }

    private fun kyAuthWordmark(
        title: String = "KyAuth",
        textSize: Float,
        iconSizeDp: Int,
        centered: Boolean = false,
    ) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = if (centered) Gravity.CENTER else Gravity.CENTER_VERTICAL
        contentDescription = title
        addView(ImageView(context).apply {
            setImageResource(R.drawable.kypost_hero)
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            scaleType = ImageView.ScaleType.CENTER_INSIDE
        }, LinearLayout.LayoutParams(dp(iconSizeDp), dp(iconSizeDp)).apply { marginEnd = dp(10) })
        addView(TextView(context).apply {
            text = title
            this.textSize = textSize
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ThemeManager.color(context, R.color.ky_heading))
            includeFontPadding = false
        })
    }

    private fun bottomNavigation() = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        background = GradientDrawable().apply {
            setColor(ThemeManager.color(this@MainActivity, R.color.ky_surface))
            setStroke(dp(1), ThemeManager.color(this@MainActivity, R.color.ky_border))
            cornerRadius = dp(32).toFloat()
        }
        setPadding(dp(4), dp(4), dp(4), dp(4))

        fun destination(label: String, tab: Tab) = Button(this@MainActivity).apply {
            text = label
            textSize = 11f
            transformationMethod = null
            isAllCaps = false
            minWidth = 0
            minHeight = 0
            includeFontPadding = false
            setPadding(dp(2), 0, dp(2), 0)
            stateListAnimator = null
            elevation = 0f
            setTextColor(ThemeManager.color(context, if (activeTab == tab) R.color.ky_cyan else R.color.ky_muted))
            background = GradientDrawable().apply {
                setColor(ThemeManager.color(context, if (activeTab == tab) R.color.ky_surface_elevated else R.color.ky_surface))
                cornerRadius = dp(22).toFloat()
            }
            layoutParams = LinearLayout.LayoutParams(0, dp(56), 1f)
            setOnClickListener {
                activeTab = tab
                renderContent()
            }
        }

        addView(destination(getString(R.string.tab_totp), Tab.VAULT))
        addView(Button(this@MainActivity).apply {
            contentDescription = "Lock KyAuth"
            minWidth = 0
            minHeight = 0
            stateListAnimator = null
            elevation = 0f
            setCompoundDrawablesWithIntrinsicBounds(0, R.drawable.ic_nav_lock, 0, 0)
            compoundDrawables[1]?.setTint(ThemeManager.color(context, R.color.ky_cyan))
            background = GradientDrawable().apply {
                setColor(ThemeManager.color(context, R.color.ky_surface_elevated))
                cornerRadius = dp(22).toFloat()
            }
            layoutParams = LinearLayout.LayoutParams(dp(56), dp(56)).apply { marginStart = dp(2); marginEnd = dp(2) }
            setOnClickListener {
                lockSensitiveState()
                renderContent()
            }
        })
        addView(destination(getString(R.string.tab_settings), Tab.SETTINGS))
    }

    private fun AlertDialog.Builder.showKyDialog(): AlertDialog {
        return create().apply {
            openDialogs.add(this)
            setOnDismissListener {
                openDialogs.remove(this)
            }
            val background = GradientDrawable().apply {
                setColor(ThemeManager.color(this@MainActivity, R.color.ky_surface))
                setStroke(dp(1), ThemeManager.color(this@MainActivity, R.color.ky_border))
                cornerRadius = dp(24).toFloat()
            }
            window?.apply {
                secureWindow(this)
                setBackgroundDrawable(background)
                setDimAmount(0.45f)
            }
            setOnShowListener {
                window?.setBackgroundDrawable(background)
                findViewById<TextView>(androidx.appcompat.R.id.alertTitle)?.apply {
                    setTextColor(ThemeManager.color(this@MainActivity, R.color.ky_heading))
                    typeface = Typeface.DEFAULT_BOLD
                }
                findViewById<TextView>(android.R.id.message)?.apply {
                    setTextColor(ThemeManager.color(this@MainActivity, R.color.ky_muted))
                }
                findViewById<TextView>(androidx.appcompat.R.id.message)?.apply {
                    setTextColor(ThemeManager.color(this@MainActivity, R.color.ky_muted))
                }
                listOf(
                    DialogInterface.BUTTON_POSITIVE,
                    DialogInterface.BUTTON_NEGATIVE,
                    DialogInterface.BUTTON_NEUTRAL,
                ).forEach { which ->
                    getButton(which)?.apply {
                        setTextColor(ThemeManager.color(this@MainActivity, R.color.ky_cyan))
                        typeface = Typeface.DEFAULT_BOLD
                    }
                }
            }
            show()
            window?.let { dialogWindow ->
                val original = dialogWindow.callback
                dialogWindow.callback = object : android.view.Window.Callback by original {
                    override fun dispatchTouchEvent(event: android.view.MotionEvent): Boolean {
                        if (event.action == android.view.MotionEvent.ACTION_DOWN && !recordVaultActivity()) return true
                        return original.dispatchTouchEvent(event)
                    }
                    override fun dispatchKeyEvent(event: android.view.KeyEvent): Boolean {
                        if (event.action == android.view.KeyEvent.ACTION_DOWN && !recordVaultActivity()) return true
                        return original.dispatchKeyEvent(event)
                    }
                }
            }
        }
    }

    private fun centeredWidthParams(top: Int = 0, bottom: Int = 0, maxWidthDp: Int) = LinearLayout.LayoutParams(
        if (isCompactWidth()) LinearLayout.LayoutParams.MATCH_PARENT else dp(cappedContentWidthDp(maxWidthDp)),
        LinearLayout.LayoutParams.WRAP_CONTENT,
    ).apply {
        gravity = Gravity.CENTER_HORIZONTAL
        topMargin = dp(top)
        bottomMargin = dp(bottom)
    }

    private fun navigationParams() = centeredWidthParams(maxWidthDp = 620).apply {
        if (isExpandedWidth()) gravity = Gravity.END
    }

    private fun scrollContentParams() = FrameLayout.LayoutParams(
        if (isCompactWidth()) FrameLayout.LayoutParams.MATCH_PARENT else dp(cappedContentWidthDp(dashboardMaxWidthDp())),
        FrameLayout.LayoutParams.WRAP_CONTENT,
    ).apply {
        gravity = Gravity.CENTER_HORIZONTAL
    }

    private fun addAdaptiveCards(container: LinearLayout, cards: List<View>) {
        if (!isExpandedWidth()) {
            cards.forEach { container.addView(it) }
            return
        }

        cards.chunked(2).forEach { rowCards ->
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                layoutParams = fullWidthParams(bottom = 12)
            }
            rowCards.forEachIndexed { index, card ->
                row.addView(card, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                    marginEnd = if (index == 0) dp(6) else 0
                    marginStart = if (index == 1) dp(6) else 0
                })
            }
            if (rowCards.size == 1) {
                row.addView(Space(this), LinearLayout.LayoutParams(0, 1, 1f).apply { marginStart = dp(6) })
            }
            container.addView(row)
        }
    }

    private fun dashboardMaxWidthDp() = if (isExpandedWidth()) 960 else 560

    private fun cappedContentWidthDp(maxWidthDp: Int) = min(maxWidthDp, availableContentWidthDp())

    private fun availableContentWidthDp() = max(1, resources.configuration.screenWidthDp - (screenEdgePaddingDp() * 2))

    private fun isCompactWidth() = resources.configuration.screenWidthDp < 600

    private fun isExpandedWidth() = resources.configuration.screenWidthDp >= 840

    private fun dismissSensitiveDialogs() {
        openDialogs.toList().forEach { dialog ->
            fun clear(view: View) {
                if (view is TextView) view.text = ""
                if (view is ViewGroup) for (index in 0 until view.childCount) clear(view.getChildAt(index))
            }
            dialog.window?.decorView?.let(::clear)
            dialog.dismiss()
        }
    }

    /** One prompt signs the revoke. Only KyIdentity refusing to drop a required factor keeps the pairing. */
    private fun unpairIdentity(account: PairedAccount) {
        val issuedAt = System.currentTimeMillis()
        val message = runCatching { DeviceRevokeClient.message(account.serverUrl, account.deviceId, issuedAt) }.getOrNull()
        val signature = message?.let { runCatching { DeviceSigningKey.initSignature() }.getOrNull() }
        if (message == null || signature == null) return finishUnpair(DeviceRevokeClient.Outcome.FAILED)
        VaultUnlockPrompt.showForSignature(this, "Unpair from KyIdentity", signature, onAuthenticated = { authenticated ->
            val signed = runCatching { DeviceSigningKey.sign(message, authenticated) }.getOrNull()
                ?: return@showForSignature finishUnpair(DeviceRevokeClient.Outcome.FAILED)
            Thread {
                val outcome = DeviceRevokeClient.revoke(account.serverUrl, account.deviceId, issuedAt, signed)
                runOnUiThread { finishUnpair(outcome) }
            }.start()
        }, onFailed = { toast("Unlock required: $it") })
    }

    private fun finishUnpair(outcome: DeviceRevokeClient.Outcome) {
        if (outcome != DeviceRevokeClient.Outcome.REQUIRED_FACTOR) {
            SecurityWipe.clearPush(this)
            DeviceSigningKey.deleteKey()
            clearPairing()
        }
        when (outcome) {
            DeviceRevokeClient.Outcome.REVOKED -> toast("Removed from KyIdentity")
            DeviceRevokeClient.Outcome.REQUIRED_FACTOR -> notice("Still paired", R.string.unpair_required_factor)
            DeviceRevokeClient.Outcome.FAILED -> notice("Unpaired on this phone", R.string.unpair_not_revoked)
        }
    }

    private fun notice(title: String, message: Int) {
        if (isFinishing || isDestroyed) return
        AlertDialog.Builder(this).setTitle(title).setMessage(getString(message)).setPositiveButton("OK", null).showKyDialog()
    }

    private fun clearPairing() {
        store.clear()
        PushStore(this).forgetRegistration()
        clearPendingChallenge()
        runCatching { KyIdentityAccount.remove(this) }
        lockSensitiveState()
        renderContent()
    }

    /** The server took an answer, already cleared from storage. Reload rather than null: a newer request may have arrived meanwhile. */
    private fun onAnswerAccepted(approved: Boolean) {
        pendingChallenge = MfaPushChallengeStore(this).load()
        Toast.makeText(this, if (approved) "Sign-in Approved" else "Sign-in Denied", Toast.LENGTH_SHORT).show()
        renderContent()
    }

    /** A pairing change invalidates any stored request: it named the old device and account. */
    private fun clearPendingChallenge() {
        pendingChallenge = null
        MfaPushChallengeStore(this).clear()
    }

    private fun lockSensitiveState() {
        AppLockManager.lock()
        isVaultLoading = false
        vaultLoadGeneration = null
        vaultLoaded = false
        pendingTotpEntry = null
        dismissSensitiveDialogs()
        totpEntries.clear()
        totpViews.clear()
        // The clipboard is left to copySensitiveText's timer: leaving the app to paste a code locks it.
    }

    private fun copyTotpCode(clipboard: ClipboardManager, code: String, remainingSeconds: Long) {
        copySensitiveText(code, remainingSeconds, clipboard)
    }

    private fun copySensitiveText(value: String, clearAfterSeconds: Long, clipboard: ClipboardManager? = null) {
        val targetClipboard = clipboard ?: getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val label = "KyAuth:${UUID.randomUUID()}"
        val clip = ClipData.newPlainText(label, value).apply {
            description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        copiedSensitiveLabel = label
        targetClipboard.setPrimaryClip(clip)
        handler.postDelayed({
            if (copiedSensitiveLabel == label && targetClipboard.primaryClipDescription?.label == label) {
                targetClipboard.clearPrimaryClip()
                copiedSensitiveLabel = null
            }
        }, clearAfterSeconds * 1_000)
    }
}
