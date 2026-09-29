# KyPost Android "Sign in with KyIdentity" Implementation Plan (4 of 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** KyPost pairs with its server through the KyIdentity account KyAuth publishes, with one biometric and no password.

**Architecture:** A `signon/` package: a pure client (`KyIdentitySignOnClient`) that reads the server's SSO config and swaps an ID token for a pairing deep link, a pin check (`AuthenticatorPin`) on the authenticator package, and `KyIdentitySignOnActivity` which drives `AccountManager.getAuthToken` and then restarts `PushPairingActivity` with the deep link exactly as `PasswordPairingActivity` does. The registration pipeline is untouched.

**Tech Stack:** Kotlin, OkHttp via injected `Call.Factory`, kotlinx.serialization, `android.accounts`, JUnit 4 with `FakeCallFactory`.

**Spec:** `kyauth-android/docs/superpowers/specs/2026-09-29-kyidentity-account-manager-signon-design.md`, section 4.

**Repo:** `/home/yoshi/git/busnes.app/kypost-android`. Branch: `feature/kyidentity-signon`.

## Global Constraints

- Account type literal `org.kysecurity.identity`. Authenticator package must be `org.kysecurity.authenticator` with a pinned certificate digest; anything else fails closed before `getAuthToken`.
- Account `server_url` user data must equal the config `issuerUrl` after trailing-slash trimming; mismatch is refused with a message naming both hosts.
- Server URL must pass `pairingEndpoint` (https, no userinfo). Both HTTP calls use `pairingHttpClient(PinPosture.TofuWindow, 15_000)` like `PasswordPairingActivity`.
- Request/response DTOs override `toString()` to `"...(redacted)"` (`SourceRulesTest`).
- No `android.*` class in `KyIdentitySignOnClient`; unit tests run with `isReturnDefaultValues = false`.
- The button is visible only when an authenticator for the account type is installed; it is not gated on `ENABLE_REVIEW_PAIRING`.
- Verification: `./gradlew testPlayDebugUnitTest lint assemblePlayDebug`.

## Review Focus

1. Server answers `enabled:false` or an empty `clientId` → a clear "this server does not use KyIdentity" message, no account picker. Pinned in Task 1 (`config_disabled`).
2. Sign-on endpoint answers 503 (pairing unconfigured) → the message names the server, not "expired token". Pinned in Task 1 (`signOn_503`).
3. Two authenticators for the type (rogue installed alongside KyAuth) → refuse. Pinned in Task 2 (`decide_refusesMultiple`).
4. The user cancels KyAuth's prompt → `OperationCanceledException` → silent return to the pairing screen, no toast about failure. Pinned by structure in Task 3; device check listed in AGENTS.md.
5. The deep link returned is parsed by `NativePairingDeepLinkParser` and therefore still passes through the host-confirm dialog; a server that returns a deep link naming another host is caught there. Pinned in Task 1 (`signOn_parsesDeepLink`) plus the existing parser tests.

---

### Task 1: `KyIdentitySignOnClient`

**Files:**
- Create: `app/src/main/java/org/kysecurity/mail/signon/KyIdentitySignOnClient.kt`
- Test: `app/src/test/java/org/kysecurity/mail/signon/KyIdentitySignOnClientTest.kt`

**Interfaces:**
- Produces:
  - `data class SignOnConfig(val issuerUrl: String, val clientId: String)`
  - `sealed class SignOnConfigResult { data class Ready(val config: SignOnConfig); data class Unavailable(val reason: String) }`
  - `class KyIdentitySignOnClient(callFactory: Call.Factory, json: Json = Json { ignoreUnknownKeys = true }) { suspend fun config(serverUrl: String): SignOnConfigResult; suspend fun signOn(serverUrl: String, idToken: String): PairingParseResult }`

- [ ] **Step 1: Write the failing tests**

```kotlin
package org.kysecurity.mail.signon

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kysecurity.mail.push.PairingParseResult
import org.kysecurity.mail.testing.BodyRecordingCallFactory
import org.kysecurity.mail.testing.FakeCallFactory
import org.kysecurity.mail.testing.response

class KyIdentitySignOnClientTest {
    private val server = "https://mail.example.com"

    @Test
    fun config_ready() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, """{"enabled":true,"issuerUrl":"https://id.example.com/","clientId":"kypost"}""", 200) }
        val r = KyIdentitySignOnClient(factory).config(server) as SignOnConfigResult.Ready
        assertEquals("https://id.example.com", r.config.issuerUrl)
        assertEquals("kypost", r.config.clientId)
        assertEquals("$server/api/auth/sso-config", factory.requests.single().url.toString())
    }

    @Test
    fun config_disabled() = runBlocking {
        val off = FakeCallFactory { req -> response(req, """{"enabled":false,"issuerUrl":""}""", 200) }
        assertTrue(KyIdentitySignOnClient(off).config(server) is SignOnConfigResult.Unavailable)
        val noClient = FakeCallFactory { req -> response(req, """{"enabled":true,"issuerUrl":"https://id.example.com"}""", 200) }
        assertTrue(KyIdentitySignOnClient(noClient).config(server) is SignOnConfigResult.Unavailable)
    }

    @Test
    fun config_rejectsHttpServer() = runBlocking {
        val r = KyIdentitySignOnClient(FakeCallFactory { req -> response(req, "{}", 200) }).config("http://mail.example.com")
        assertTrue(r is SignOnConfigResult.Unavailable)
    }

    @Test
    fun signOn_parsesDeepLink() = runBlocking {
        val link = "kypost://native-pair?sub=s1&srv=https%3A%2F%2Fmail.example.com&reg=https%3A%2F%2Fmail.example.com%2Fapi%2Fnotifications%2Fnative%2Fregister&pt=tok"
        val factory = BodyRecordingCallFactory { req -> response(req, """{"configured":true,"deepLink":"$link"}""", 200) }
        val r = KyIdentitySignOnClient(factory).signOn(server, "eyJ.a.b") as PairingParseResult.Success
        assertEquals("tok", r.pairing.pairingToken)
        assertEquals("$server/api/auth/native/signon", factory.requests.single().url.toString())
        assertEquals("""{"idToken":"eyJ.a.b"}""", factory.bodies.single())
    }

    @Test
    fun signOn_mapsStatuses() = runBlocking {
        fun at(code: Int, body: String = "") = KyIdentitySignOnClient(FakeCallFactory { req -> response(req, body, code) }).signOn(server, "t") as PairingParseResult.Error
        assertTrue(at(503).reason.contains("mail.example.com"))
        assertTrue(at(403, "Access denied: this token was already used.").reason.contains("already used"))
        assertTrue(at(429).reason.contains("Try again"))
        assertTrue(at(200, """{"configured":false,"configurationError":"set PAIRING_SECRET"}""").reason.contains("PAIRING_SECRET"))
    }

    @Test
    fun dtos_redact() {
        assertEquals("SignOnRequest(redacted)", SignOnRequest("secret").toString())
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `./gradlew testPlayDebugUnitTest --tests 'org.kysecurity.mail.signon.KyIdentitySignOnClientTest'`
Expected: FAIL, unresolved `KyIdentitySignOnClient`.

- [ ] **Step 3: Implement**

```kotlin
package org.kysecurity.mail.signon

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.kysecurity.mail.executeSync
import org.kysecurity.mail.push.NativePairingDeepLinkParser
import org.kysecurity.mail.push.PairingParseResult
import org.kysecurity.mail.push.pairingEndpoint

data class SignOnConfig(val issuerUrl: String, val clientId: String)

sealed class SignOnConfigResult {
    data class Ready(val config: SignOnConfig) : SignOnConfigResult()
    data class Unavailable(val reason: String) : SignOnConfigResult()
}

@Serializable
private data class SsoConfigResponse(
    @SerialName("enabled") val enabled: Boolean = false,
    @SerialName("issuerUrl") val issuerUrl: String = "",
    @SerialName("clientId") val clientId: String = "",
) {
    override fun toString(): String = "SsoConfigResponse(redacted)"
}

@Serializable
internal data class SignOnRequest(@SerialName("idToken") val idToken: String) {
    override fun toString(): String = "SignOnRequest(redacted)"
}

@Serializable
private data class SignOnResponse(
    @SerialName("configured") val configured: Boolean = false,
    @SerialName("configurationError") val configurationError: String = "",
    @SerialName("deepLink") val deepLink: String = "",
) {
    override fun toString(): String = "SignOnResponse(redacted)"
}

/** Reads the relay's SSO config and swaps a KyIdentity ID token for a pairing deep link. */
class KyIdentitySignOnClient(
    private val callFactory: Call.Factory,
    private val json: Json = Json { ignoreUnknownKeys = true },
) {
    suspend fun config(serverUrl: String): SignOnConfigResult {
        val endpoint = pairingEndpoint(serverUrl, "/api/auth/sso-config")
            ?: return SignOnConfigResult.Unavailable("Server URL must use https")
        val request = Request.Builder().url(endpoint).get().build()
        val result = withContext(Dispatchers.IO) {
            callFactory.executeSync(request) { response -> response.code to response.body?.string().orEmpty() }
        }
        val (code, raw) = result.getOrNull()
            ?: return SignOnConfigResult.Unavailable(result.exceptionOrNull()?.message ?: "Could not reach the server")
        if (code != 200) return SignOnConfigResult.Unavailable("Could not read the server's sign-in settings ($code)")
        val body = runCatching { json.decodeFromString<SsoConfigResponse>(raw) }.getOrNull()
            ?: return SignOnConfigResult.Unavailable("The server returned an unreadable sign-in configuration")
        if (!body.enabled || body.issuerUrl.isBlank() || body.clientId.isBlank()) {
            return SignOnConfigResult.Unavailable("This server does not use KyIdentity sign-in")
        }
        return SignOnConfigResult.Ready(SignOnConfig(body.issuerUrl.trimEnd('/'), body.clientId))
    }

    suspend fun signOn(serverUrl: String, idToken: String): PairingParseResult {
        val endpoint = pairingEndpoint(serverUrl, "/api/auth/native/signon")
            ?: return PairingParseResult.Error("Server URL must use https")
        val request = Request.Builder()
            .url(endpoint)
            .post(json.encodeToString(SignOnRequest(idToken)).toRequestBody("application/json".toMediaType()))
            .build()
        val result = withContext(Dispatchers.IO) {
            callFactory.executeSync(request) { response -> response.code to response.body?.string().orEmpty() }
        }
        val (code, raw) = result.getOrNull()
            ?: return PairingParseResult.Error(result.exceptionOrNull()?.message ?: "Could not reach the server")
        if (code != 200) {
            val host = endpoint.host
            val message = when (code) {
                403 -> raw.trim().ifBlank { "KyIdentity sign-in was refused" }
                429 -> "Too many attempts. Try again later"
                503 -> "$host is not set up for KyIdentity sign-in or pairing"
                else -> "Could not sign in to $host ($code)"
            }
            return PairingParseResult.Error(message)
        }
        val body = runCatching { json.decodeFromString<SignOnResponse>(raw) }.getOrNull()
            ?: return PairingParseResult.Error("The server returned an unreadable pairing response")
        if (!body.configured || body.deepLink.isBlank()) {
            return PairingParseResult.Error(body.configurationError.ifBlank { "Pairing is not configured on the server" })
        }
        return NativePairingDeepLinkParser.parse(body.deepLink)
    }
}
```

`executeSync` is the extension `PasswordPairingClient` uses; import it from wherever it is declared (`grep -rn "fun Call.Factory.executeSync" app/src/main/java`).

- [ ] **Step 4: Run tests**

Run: `./gradlew testPlayDebugUnitTest --tests 'org.kysecurity.mail.signon.*' --tests 'org.kysecurity.mail.SourceRulesTest'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/org/kysecurity/mail/signon/KyIdentitySignOnClient.kt app/src/test/java/org/kysecurity/mail/signon/KyIdentitySignOnClientTest.kt
git commit -m "feat(signon): client for the relay's KyIdentity sign-on endpoint"
```

---

### Task 2: `AuthenticatorPin`

**Files:**
- Create: `app/src/main/java/org/kysecurity/mail/signon/AuthenticatorPin.kt`
- Test: `app/src/test/java/org/kysecurity/mail/signon/AuthenticatorPinTest.kt`

**Interfaces:**
- Produces: `object AuthenticatorPin { const val ACCOUNT_TYPE = "org.kysecurity.identity"; const val KYAUTH_PACKAGE = "org.kysecurity.authenticator"; fun trustedAuthenticator(context: Context): Boolean; internal fun decide(authenticatorPackages: List<String>, certDigestsFor: (String) -> Set<String>, extraDebugDigest: String?): Boolean }`

- [ ] **Step 1: Write the failing test**

```kotlin
package org.kysecurity.mail.signon

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AuthenticatorPinTest {
    private val pinned = AuthenticatorPin.PINS.first()

    @Test
    fun decide_acceptsKyAuthWithPinnedCert() {
        assertTrue(AuthenticatorPin.decide(listOf("org.kysecurity.authenticator"), { setOf(pinned) }, null))
    }

    @Test
    fun decide_refusesWrongPackageOrCert() {
        assertFalse(AuthenticatorPin.decide(listOf("com.evil"), { setOf(pinned) }, null))
        assertFalse(AuthenticatorPin.decide(listOf("org.kysecurity.authenticator"), { setOf("00".repeat(32)) }, null))
        assertFalse(AuthenticatorPin.decide(listOf("org.kysecurity.authenticator"), { emptySet() }, null))
    }

    @Test
    fun decide_refusesMultiple() {
        assertFalse(AuthenticatorPin.decide(listOf("org.kysecurity.authenticator", "com.evil"), { setOf(pinned) }, null))
        assertFalse(AuthenticatorPin.decide(emptyList(), { setOf(pinned) }, null))
    }

    @Test
    fun decide_debugDigestOnlyWhenSupplied() {
        val debug = "ab".repeat(32)
        assertFalse(AuthenticatorPin.decide(listOf("org.kysecurity.authenticator"), { setOf(debug) }, null))
        assertTrue(AuthenticatorPin.decide(listOf("org.kysecurity.authenticator"), { setOf(debug) }, debug))
    }

    @Test
    fun pins_areRealDigests() {
        assertFalse(AuthenticatorPin.PINS.any { it.startsWith("REPLACE") })
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./gradlew testPlayDebugUnitTest --tests 'org.kysecurity.mail.signon.AuthenticatorPinTest'`
Expected: FAIL, unresolved `AuthenticatorPin`.

- [ ] **Step 3: Implement**

Get KyAuth's release digest: `keytool -list -v -keystore /home/yoshi/keystores/KyAuth-release.jks -alias kyauth-release | grep SHA256`, lowercase hex, no colons. If KyAuth ships through Play App Signing, add that key's digest too.

```kotlin
package org.kysecurity.mail.signon

import android.accounts.AccountManager
import android.content.Context
import android.content.pm.PackageManager
import org.kysecurity.mail.BuildConfig
import java.security.MessageDigest

/**
 * Only KyAuth may answer for the KyIdentity account type. The system routes by account type, so a
 * rogue app registering the same type would receive our getAuthToken and could phish the prompt.
 * Its token would fail at the relay, but the prompt is the user's, so refuse before asking.
 */
object AuthenticatorPin {
    const val ACCOUNT_TYPE = "org.kysecurity.identity"
    const val KYAUTH_PACKAGE = "org.kysecurity.authenticator"

    internal val PINS: Set<String> = setOf(
        "REPLACE_WITH_KYAUTH_RELEASE_SHA256",
    )

    fun trustedAuthenticator(context: Context): Boolean {
        val packages = AccountManager.get(context).authenticatorTypes
            .filter { it.type == ACCOUNT_TYPE }
            .map { it.packageName }
        val debug = BuildConfig.DEBUG_KYAUTH_CERT.takeIf { BuildConfig.DEBUG && it.isNotBlank() }
        return decide(packages, { pkg -> signingDigests(context.packageManager, pkg) }, debug)
    }

    internal fun decide(
        authenticatorPackages: List<String>,
        certDigestsFor: (String) -> Set<String>,
        extraDebugDigest: String?,
    ): Boolean {
        val pkg = authenticatorPackages.singleOrNull() ?: return false
        if (pkg != KYAUTH_PACKAGE) return false
        val allowed = if (extraDebugDigest != null) PINS + extraDebugDigest else PINS
        val actual = certDigestsFor(pkg)
        return actual.isNotEmpty() && allowed.containsAll(actual)
    }

    private fun signingDigests(pm: PackageManager, pkg: String): Set<String> = runCatching {
        val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
        val signing = info.signingInfo ?: return emptySet()
        if (signing.hasMultipleSigners()) return emptySet()
        signing.signingCertificateHistory.map { sig ->
            MessageDigest.getInstance("SHA-256").digest(sig.toByteArray()).joinToString("") { "%02x".format(it) }
        }.toSet()
    }.getOrDefault(emptySet())
}
```

`app/build.gradle.kts` `defaultConfig`:

```kotlin
        buildConfigField("String", "DEBUG_KYAUTH_CERT", "\"${providers.gradleProperty("kypostDebugKyAuthCert").orNull.orEmpty()}\"")
```

Confirm `buildFeatures { buildConfig = true }` is already on (it is: `BuildConfig.ENABLE_REVIEW_PAIRING` exists).

- [ ] **Step 4: Run tests**

Run: `./gradlew testPlayDebugUnitTest --tests 'org.kysecurity.mail.signon.AuthenticatorPinTest'`
Expected: PASS once the real digest replaces the placeholder.

- [ ] **Step 5: Commit**

```bash
git add app/build.gradle.kts app/src/main/java/org/kysecurity/mail/signon/AuthenticatorPin.kt app/src/test/java/org/kysecurity/mail/signon/AuthenticatorPinTest.kt
git commit -m "feat(signon): pin KyAuth as the only KyIdentity authenticator"
```

---

### Task 3: `KyIdentitySignOnActivity` and the pairing-screen button

**Files:**
- Create: `app/src/main/java/org/kysecurity/mail/signon/KyIdentitySignOnActivity.kt`
- Create: `app/src/main/res/layout/activity_kyidentity_signon.xml`
- Modify: `app/src/main/res/values/strings.xml`
- Modify: `app/src/main/res/layout/activity_push_pairing.xml` (button above `btnPasswordPairing`)
- Modify: `app/src/main/java/org/kysecurity/mail/push/PushPairingActivity.kt` (`initViews`, click handler, visibility)
- Modify: `app/src/main/AndroidManifest.xml` (activity next to `PasswordPairingActivity`)

- [ ] **Step 1: Layout and strings**

`activity_kyidentity_signon.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:id="@+id/kyIdentitySignOnRoot"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:orientation="vertical"
    android:padding="24dp">

    <TextView
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:layout_marginBottom="24dp"
        android:text="@string/kyidentity_signon_intro"
        android:textSize="16sp" />

    <EditText
        android:id="@+id/kyIdentitySignOnServer"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:autofillHints="url"
        android:hint="@string/password_pairing_server"
        android:imeOptions="actionDone"
        android:inputType="textUri"
        android:singleLine="true" />

    <TextView
        android:id="@+id/kyIdentitySignOnStatus"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:layout_marginTop="12dp"
        android:textSize="14sp" />

    <Button
        android:id="@+id/btnKyIdentitySignOn"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:layout_marginTop="24dp"
        android:text="@string/kyidentity_signon_action" />
</LinearLayout>
```

`strings.xml`:

```xml
    <string name="kyidentity_signon_open">Sign in with KyIdentity</string>
    <string name="kyidentity_signon_title">Sign in with KyIdentity</string>
    <string name="kyidentity_signon_intro">Enter your KyPost server address. KyAuth will ask you to approve the sign-in with your fingerprint or screen lock.</string>
    <string name="kyidentity_signon_action">Continue with KyAuth</string>
    <string name="kyidentity_signon_no_authenticator">KyAuth is not installed or is not the app providing KyIdentity accounts on this phone.</string>
    <string name="kyidentity_signon_issuer_mismatch">This server signs in through %1$s, but your KyAuth account belongs to %2$s.</string>
```

`activity_push_pairing.xml`, directly above `btnPasswordPairing`:

```xml
    <Button
        android:id="@+id/btnKyIdentitySignOn"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:layout_marginStart="16dp"
        android:layout_marginEnd="16dp"
        android:layout_marginTop="8dp"
        android:text="@string/kyidentity_signon_open" />
```

- [ ] **Step 2: Wire the pairing screen**

`PushPairingActivity.kt`: declare `private lateinit var btnKyIdentitySignOn: Button`; in `initViews` after `btnPasswordPairing`:

```kotlin
        btnKyIdentitySignOn = findViewById(R.id.btnKyIdentitySignOn)
        btnKyIdentitySignOn.visibility = if (AuthenticatorPin.trustedAuthenticator(this)) View.VISIBLE else View.GONE
```

in `onCreateUnlocked` next to the password button's listener:

```kotlin
        btnKyIdentitySignOn.setOnClickListener { startActivity(Intent(this, KyIdentitySignOnActivity::class.java)) }
```

and in `onResume` add it to the themed buttons the way `btnPasswordPairing` is, and in `render()` to the `isEnabled = !state.isWorking` set. Import `org.kysecurity.mail.signon.AuthenticatorPin` and `org.kysecurity.mail.signon.KyIdentitySignOnActivity`.

Manifest, after `PasswordPairingActivity`:

```xml
        <activity
            android:name=".signon.KyIdentitySignOnActivity"
            android:exported="false"
            android:windowSoftInputMode="adjustResize" />
```

- [ ] **Step 3: The activity**

```kotlin
package org.kysecurity.mail.signon

import android.accounts.Account
import android.accounts.AccountManager
import android.accounts.AuthenticatorException
import android.accounts.OperationCanceledException
import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.kysecurity.mail.PinPosture
import org.kysecurity.mail.R
import org.kysecurity.mail.applyPrimaryButtonTheme
import org.kysecurity.mail.applyThemeToActivity
import org.kysecurity.mail.applyTopInsetWithHeader
import org.kysecurity.mail.pairingHttpClient
import org.kysecurity.mail.push.PairingData
import org.kysecurity.mail.push.PairingParseResult
import org.kysecurity.mail.push.PushPairingActivity
import org.kysecurity.mail.security.LockedActivity

/**
 * Pairs through the KyIdentity account KyAuth publishes: read the relay's SSO config, get an ID
 * token from AccountManager (KyAuth prompts), swap it for a pairing deep link, then hand that link
 * to the ordinary pairing flow so registration, TLS pinning and secret storage stay unchanged.
 */
class KyIdentitySignOnActivity : LockedActivity() {
    private lateinit var button: Button
    private lateinit var status: TextView
    private var pendingConfig: SignOnConfig? = null

    private val chooseAccount = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val name = result.data?.getStringExtra(AccountManager.KEY_ACCOUNT_NAME)
        val type = result.data?.getStringExtra(AccountManager.KEY_ACCOUNT_TYPE)
        val config = pendingConfig
        if (name != null && type == AuthenticatorPin.ACCOUNT_TYPE && config != null) {
            requestToken(Account(name, type), config)
        } else {
            button.isEnabled = true
        }
    }

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        setContentView(R.layout.activity_kyidentity_signon)
        setTitle(R.string.kyidentity_signon_title)
        applyTopInsetWithHeader(this, findViewById(R.id.kyIdentitySignOnRoot))
        button = findViewById(R.id.btnKyIdentitySignOn)
        status = findViewById(R.id.kyIdentitySignOnStatus)
        button.setOnClickListener { start() }
        applyThemeToActivity(this)
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return
        applyThemeToActivity(this)
        applyPrimaryButtonTheme(this, button)
    }

    private fun start() {
        if (!AuthenticatorPin.trustedAuthenticator(this)) {
            status.setText(R.string.kyidentity_signon_no_authenticator)
            return
        }
        val server = findViewById<EditText>(R.id.kyIdentitySignOnServer).text.toString().trim()
        button.isEnabled = false
        status.text = ""
        lifecycleScope.launch {
            val client = KyIdentitySignOnClient(pairingHttpClient(PinPosture.TofuWindow, 15_000))
            when (val cfg = client.config(server)) {
                is SignOnConfigResult.Unavailable -> { status.text = cfg.reason; button.isEnabled = true }
                is SignOnConfigResult.Ready -> pickAccount(cfg.config)
            }
        }
    }

    private fun pickAccount(config: SignOnConfig) {
        pendingConfig = config
        val am = AccountManager.get(this)
        val accounts = am.getAccountsByType(AuthenticatorPin.ACCOUNT_TYPE)
        if (accounts.size == 1) {
            requestToken(accounts[0], config)
            return
        }
        // Zero visible accounts (KyAuth may hold one we cannot see yet) or several: let the system ask.
        chooseAccount.launch(
            AccountManager.newChooseAccountIntent(null, null, arrayOf(AuthenticatorPin.ACCOUNT_TYPE), null, null, null, null),
        )
    }

    private fun requestToken(account: Account, config: SignOnConfig) {
        val am = AccountManager.get(this)
        val issuer = am.getUserData(account, "server_url")?.trimEnd('/')
        if (issuer != config.issuerUrl) {
            status.text = getString(R.string.kyidentity_signon_issuer_mismatch, config.issuerUrl, issuer ?: "another server")
            button.isEnabled = true
            return
        }
        lifecycleScope.launch {
            val token = withContext(Dispatchers.IO) {
                runCatching {
                    am.getAuthToken(account, config.clientId, null, this@KyIdentitySignOnActivity, null, null)
                        .result.getString(AccountManager.KEY_AUTHTOKEN)
                }
            }
            token.onFailure { e ->
                button.isEnabled = true
                when (e) {
                    is OperationCanceledException -> Unit
                    is AuthenticatorException -> status.text = e.message ?: "KyAuth refused the sign-in"
                    else -> status.text = e.message ?: "Could not get a sign-in token from KyAuth"
                }
            }.onSuccess { idToken ->
                if (idToken.isNullOrBlank()) {
                    status.text = "KyAuth returned no token"
                    button.isEnabled = true
                    return@onSuccess
                }
                exchange(idToken)
            }
        }
    }

    private suspend fun exchange(idToken: String) {
        val server = findViewById<EditText>(R.id.kyIdentitySignOnServer).text.toString().trim()
        val result = KyIdentitySignOnClient(pairingHttpClient(PinPosture.TofuWindow, 15_000)).signOn(server, idToken)
        button.isEnabled = true
        when (result) {
            is PairingParseResult.Error -> Toast.makeText(this, result.reason, Toast.LENGTH_LONG).show()
            is PairingParseResult.Success -> {
                startActivity(Intent(this, PushPairingActivity::class.java).apply {
                    data = android.net.Uri.parse(pairingDeepLink(result.pairing))
                })
                finish()
            }
        }
    }
}

private fun pairingDeepLink(pairing: PairingData): String = android.net.Uri.Builder()
    .scheme("kypost")
    .authority("native-pair")
    .appendQueryParameter("sub", pairing.subscriberId)
    .appendQueryParameter("srv", pairing.serverUrl)
    .appendQueryParameter("reg", pairing.registrationUrl)
    .appendQueryParameter("pt", pairing.pairingToken)
    .apply { pairing.spkiPin?.let { appendQueryParameter("pin", it) } }
    .build()
    .toString()
```

`pairingDeepLink` duplicates the private function in `PasswordPairingActivity.kt`. Move that one into `push/PairingModels.kt` as `internal fun pairingDeepLink(pairing: PairingData): String` and call it from both activities instead of duplicating.

`getAuthToken(..., activity, ...)` shows KyAuth's `SignOnActivity` via `KEY_INTENT` automatically because an `Activity` is passed. `.result` blocks; it runs on `Dispatchers.IO`.

- [ ] **Step 4: Build, lint, test**

Run: `./gradlew testPlayDebugUnitTest lint assemblePlayDebug`
Expected: PASS; lint clean.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/org/kysecurity/mail/signon app/src/main/java/org/kysecurity/mail/push app/src/main/res/layout app/src/main/res/values/strings.xml app/src/main/AndroidManifest.xml
git commit -m "feat(signon): sign in with the KyIdentity account KyAuth publishes"
```

---

### Task 4: Docs and device checklist

**Files:**
- Modify: `AGENTS.md` (root, near line 13 pairing bullet)
- Modify: `app/src/main/AGENTS.md` (pairing bullets ~13-25)

- [ ] **Step 1: Root AGENTS.md**

Add after the pairing bullet:

- A third way in: "Sign in with KyIdentity" (`signon/`). Visible only when `AuthenticatorPin.trustedAuthenticator` sees exactly one authenticator for `org.kysecurity.identity`, and it is `org.kysecurity.authenticator` with a pinned signing certificate. The activity reads `GET /api/auth/sso-config` (`issuerUrl`, `clientId`), requires the account's `server_url` to equal `issuerUrl`, calls `AccountManager.getAuthToken(account, clientId, …)` (KyAuth prompts and returns a short-lived ID token), posts it to `POST /api/auth/native/signon` and receives the same `kypost://native-pair` deep link the password path receives. Everything after that is the normal pairing pipeline. The token is never stored.

- [ ] **Step 2: app/src/main/AGENTS.md**

Add one bullet: "`KyIdentitySignOnClient` has no Android imports so it runs under `isReturnDefaultValues=false`; `AuthenticatorPin.decide` is the pure half of the pin. Debug builds accept `kypostDebugKyAuthCert` for a debug-signed KyAuth. Unverified on hardware: cancelling KyAuth's prompt returns to the pairing screen silently; `newChooseAccountIntent` grants visibility to an account KyAuth created before KyPost was installed."

- [ ] **Step 3: Full verification and commit**

Run: `./gradlew testPlayDebugUnitTest lint assemblePlayDebug`
Expected: PASS.

```bash
git add AGENTS.md app/src/main/AGENTS.md
git commit -m "docs: KyIdentity sign-in path"
```

---

## Cross-repo device verification (after all four plans)

Deploy KyIdentity and kypost-server, install KyAuth and KyPost on one phone, then:

1. In KyIdentity, pair the phone with "Allow this phone to sign in to suite apps" checked. Settings → Passwords & accounts on the phone shows a KyIdentity account.
2. In KyPost, tap "Sign in with KyIdentity", enter the relay URL. KyAuth's prompt names KyPost and the username; approve with biometric. KyPost shows the host-confirm dialog, then "paired".
3. In KyIdentity, turn the device's "Sign in to apps" switch off. Repeat step 2: KyAuth reports sign-in is off for this device and the system account disappears.
4. Turn it back on, re-pair KyAuth, repeat step 2: works.
5. Cancel the biometric: KyPost returns to the pairing screen with no error toast.
6. Remove the account from phone Settings, open KyAuth Settings: "Restore system account" recreates it.

Record each result in the respective AGENTS.md "unverified" lists, replacing the unverified note with the observed behaviour.
