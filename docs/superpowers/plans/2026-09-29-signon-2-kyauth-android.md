# KyAuth AccountManager authenticator Implementation Plan (2 of 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** KyAuth hosts the `org.kysecurity.identity` account and hands pinned suite apps a short-lived KyIdentity ID token after one biometric.

**Architecture:** A new `signon/` package: pure assertion building (`DeviceAssertion`), a certificate pin table (`TrustedConsumers`), account lifecycle (`KyIdentityAccount`), the `AbstractAccountAuthenticator` with `customTokens=true`, and `SignOnActivity` which prompts, signs with the existing `DeviceSigningKey`, posts the grant and returns the token. Nothing new touches `VaultKek`.

**Tech Stack:** Kotlin, `android.accounts`, `androidx.biometric`, `HttpURLConnection` + `org.json` (as `PairingClient`), JUnit 4 unit tests without Robolectric.

**Spec:** `docs/superpowers/specs/2026-09-29-kyidentity-account-manager-signon-design.md`, section 2.

**Repo:** `/home/yoshi/git/busnes.app/kyauth-android`. Branch: `feature/account-manager-signon` from `main` (after plan 1 is merged in KyIdentity, but the client can be built and unit-tested before).

## Global Constraints

- Account type is the literal `org.kysecurity.identity`. `customTokens="true"`. Account password is always `null`; user data holds only `server_url`, `user_id`, `device_id`.
- Assertion: header `{"alg":"ES256","typ":"JWT","kid":"<device_id>"}`; claims `iss=device:<device_id>`, `sub=<user_id>`, `aud=<server_url>/oauth/token`, `client_id`, `iat=now`, `exp=now+120`, `jti`=random UUID. Signature is raw `r||s`, 64 bytes, base64url without padding.
- `authTokenType` must match `[A-Za-z0-9._:-]{1,128}`; anything else is refused before any UI.
- The caller's signing certificate must be in `TrustedConsumers` (release digests only). Debug builds additionally accept `BuildConfig.DEBUG_CONSUMER_CERT` from Gradle property `kyauthDebugConsumerCert`, never a hardcoded value.
- The token is delivered once via `AccountAuthenticatorResponse`; never persisted, never logged.
- Sign-on works while the vault is locked; it must not call `AppLockManager.useVaultKeys` or `VaultUnlockPrompt.show`.
- Server URL must be HTTPS except loopback in debug (`PairingEndpoint` already enforces this for pairing; reuse its check).
- Verification: `./gradlew test lintDebug assembleDebug compileDebugAndroidTestSources`.

## Review Focus

1. A caller UID that maps to two package names (shared UID) where only one is pinned → refuse. Pinned in Task 2 (`isTrusted_requiresEveryPackageOfUid`).
2. `getAuthToken` while the device is not paired at all (account exists from a stale install) → `ERROR_CODE_BAD_REQUEST`, and the stale account is removed. Pinned in Task 4 test on the pure decision function.
3. Server answers 200 with a body lacking `id_token` → error, not an empty token. Pinned in Task 5 (`parseTokenResponse_missingIdToken`).
4. Server answers `invalid_grant` with `device_signon_disabled` → the user sees the "re-enable on the KyIdentity devices page" message. Pinned in Task 5.
5. Biometric cancelled → `ERROR_CODE_CANCELED`, no network call. Pinned in Task 6 by structure (network runs only inside `onAuthenticated`); manual device check listed in AGENTS.md.

---

### Task 1: `DeviceAssertion` — pure JWS builder

**Files:**
- Create: `app/src/main/java/org/kysecurity/authenticator/signon/DeviceAssertion.kt`
- Test: `app/src/test/java/org/kysecurity/authenticator/signon/DeviceAssertionTest.kt`

**Interfaces:**
- Produces:
  - `object DeviceAssertion { fun signingInput(deviceId, userId, serverUrl, clientId, nowEpochSeconds, jti): String; fun derToRaw(der: ByteArray): ByteArray; fun compact(signingInput: String, rawSignature: ByteArray): String; fun isValidClientId(s: String?): Boolean }`
  - `const val ASSERTION_TTL_SECONDS = 120L`

- [ ] **Step 1: Write the failing tests**

```kotlin
package org.kysecurity.authenticator.signon

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class DeviceAssertionTest {
    private fun b64url(s: String): ByteArray = Base64.getUrlDecoder().decode(s)

    @Test
    fun signingInput_hasPinnedHeaderAndClaims() {
        val input = DeviceAssertion.signingInput(
            deviceId = "dev-1", userId = "user-1", serverUrl = "https://id.example.com/",
            clientId = "kypost", nowEpochSeconds = 1000, jti = "j-1",
        )
        val (h, c) = input.split(".").let { it[0] to it[1] }
        assertEquals("""{"alg":"ES256","typ":"JWT","kid":"dev-1"}""", String(b64url(h)))
        val claims = JSONObject(String(b64url(c)))
        assertEquals("device:dev-1", claims.getString("iss"))
        assertEquals("user-1", claims.getString("sub"))
        assertEquals("https://id.example.com/oauth/token", claims.getString("aud"))
        assertEquals("kypost", claims.getString("client_id"))
        assertEquals(1000L, claims.getLong("iat"))
        assertEquals(1120L, claims.getLong("exp"))
        assertEquals("j-1", claims.getString("jti"))
        assertEquals(7, claims.length())
    }

    @Test
    fun derToRaw_producesSixtyFourBytesThatVerify() {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val input = "a.b".toByteArray()
        val der = Signature.getInstance("SHA256withECDSA").apply { initSign(kp.private); update(input) }.sign()
        val raw = DeviceAssertion.derToRaw(der)
        assertEquals(64, raw.size)
        val r = BigInteger(1, raw.copyOfRange(0, 32))
        val s = BigInteger(1, raw.copyOfRange(32, 64))
        // Re-encode to DER and verify with the JCA to prove r||s carries the same signature.
        val reDer = derFromRaw(r, s)
        val ok = Signature.getInstance("SHA256withECDSA").apply { initVerify(kp.public); update(input) }.verify(reDer)
        assertTrue(ok)
    }

    @Test
    fun compact_isThreeSegmentsUnpaddedBase64Url() {
        val out = DeviceAssertion.compact("h.c", ByteArray(64) { 0xff.toByte() })
        val parts = out.split(".")
        assertEquals(3, parts.size)
        assertFalse(parts[2].contains("="))
        assertFalse(parts[2].contains("+"))
        assertFalse(parts[2].contains("/"))
        assertEquals(64, b64url(parts[2]).size)
    }

    @Test
    fun isValidClientId_boundsCharsetAndLength() {
        assertTrue(DeviceAssertion.isValidClientId("kypost.prod_1:eu-2"))
        assertFalse(DeviceAssertion.isValidClientId(null))
        assertFalse(DeviceAssertion.isValidClientId(""))
        assertFalse(DeviceAssertion.isValidClientId("has space"))
        assertFalse(DeviceAssertion.isValidClientId("x".repeat(129)))
    }

    private fun derFromRaw(r: BigInteger, s: BigInteger): ByteArray {
        fun int(v: BigInteger): ByteArray { val b = v.toByteArray(); return byteArrayOf(0x02, b.size.toByte()) + b }
        val body = int(r) + int(s)
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `./gradlew test --tests 'org.kysecurity.authenticator.signon.DeviceAssertionTest'`
Expected: FAIL, unresolved reference `DeviceAssertion`.

- [ ] **Step 3: Implement**

```kotlin
package org.kysecurity.authenticator.signon

import org.json.JSONObject
import java.math.BigInteger
import java.util.Base64

const val ASSERTION_TTL_SECONDS = 120L

/**
 * Builds the RFC 7523 assertion KyIdentity's jwt-bearer grant verifies. Pure: the caller
 * signs [signingInput] with the device key and feeds the DER result through [derToRaw].
 */
object DeviceAssertion {
    private val CLIENT_ID = Regex("[A-Za-z0-9._:-]{1,128}")
    private val b64 = Base64.getUrlEncoder().withoutPadding()

    fun isValidClientId(value: String?): Boolean = value != null && CLIENT_ID.matches(value)

    fun signingInput(
        deviceId: String,
        userId: String,
        serverUrl: String,
        clientId: String,
        nowEpochSeconds: Long,
        jti: String,
    ): String {
        val header = JSONObject().put("alg", "ES256").put("typ", "JWT").put("kid", deviceId)
        val claims = JSONObject()
            .put("iss", "device:$deviceId")
            .put("sub", userId)
            .put("aud", serverUrl.trimEnd('/') + "/oauth/token")
            .put("client_id", clientId)
            .put("iat", nowEpochSeconds)
            .put("exp", nowEpochSeconds + ASSERTION_TTL_SECONDS)
            .put("jti", jti)
        return b64.encodeToString(header.toString().toByteArray()) + "." +
            b64.encodeToString(claims.toString().toByteArray())
    }

    /** DER `SEQUENCE { INTEGER r, INTEGER s }` from the JCA to the 64-byte `r||s` JWS expects. */
    fun derToRaw(der: ByteArray): ByteArray {
        require(der.size > 8 && der[0] == 0x30.toByte()) { "Not a DER ECDSA signature" }
        var i = 2
        if (der[1].toInt() and 0x80 != 0) i += der[1].toInt() and 0x7f // long-form length
        fun readInt(): BigInteger {
            require(der[i] == 0x02.toByte()) { "Expected INTEGER" }
            val len = der[i + 1].toInt() and 0xff
            val v = BigInteger(1, der.copyOfRange(i + 2, i + 2 + len))
            i += 2 + len
            return v
        }
        val r = readInt()
        val s = readInt()
        val out = ByteArray(64)
        r.toByteArray().takeLast(32).toByteArray().copyInto(out, 32 - minOf(32, r.toByteArray().takeLast(32).size))
        s.toByteArray().takeLast(32).toByteArray().copyInto(out, 64 - minOf(32, s.toByteArray().takeLast(32).size))
        return out
    }

    fun compact(signingInput: String, rawSignature: ByteArray): String =
        signingInput + "." + b64.encodeToString(rawSignature)
}
```

Simplify `derToRaw`'s tail if you can express the left-padding more plainly; the test is the contract.

- [ ] **Step 4: Run tests**

Run: `./gradlew test --tests 'org.kysecurity.authenticator.signon.DeviceAssertionTest'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/org/kysecurity/authenticator/signon/DeviceAssertion.kt app/src/test/java/org/kysecurity/authenticator/signon/DeviceAssertionTest.kt
git commit -m "feat(signon): pure ES256 device assertion builder"
```

---

### Task 2: `TrustedConsumers` — caller certificate pin

**Files:**
- Create: `app/src/main/java/org/kysecurity/authenticator/signon/TrustedConsumers.kt`
- Modify: `app/build.gradle.kts` (add `buildConfigField("String", "DEBUG_CONSUMER_CERT", ...)`)
- Test: `app/src/test/java/org/kysecurity/authenticator/signon/TrustedConsumersTest.kt`

**Interfaces:**
- Produces:
  - `object TrustedConsumers { fun isTrusted(context: Context, callerUid: Int): TrustedCaller?; internal fun decide(packagesForUid: List<String>, certDigestsFor: (String) -> Set<String>, extraDebugDigest: String?): TrustedCaller? }`
  - `data class TrustedCaller(val packageName: String, val label: String)`

- [ ] **Step 1: Write the failing test**

```kotlin
package org.kysecurity.authenticator.signon

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class TrustedConsumersTest {
    private val play = TrustedConsumers.PINS.getValue("org.kysecurity.mail").first()

    @Test
    fun decide_acceptsPinnedPackageWithPinnedCert() {
        val caller = TrustedConsumers.decide(listOf("org.kysecurity.mail"), { setOf(play) }, null)
        assertEquals("org.kysecurity.mail", caller?.packageName)
        assertEquals("KyPost", caller?.label)
    }

    @Test
    fun decide_refusesUnknownCert() {
        assertNull(TrustedConsumers.decide(listOf("org.kysecurity.mail"), { setOf("00".repeat(32)) }, null))
    }

    @Test
    fun decide_refusesUnknownPackage() {
        assertNull(TrustedConsumers.decide(listOf("com.evil.app"), { setOf(play) }, null))
    }

    @Test
    fun isTrusted_requiresEveryPackageOfUid() {
        assertNull(TrustedConsumers.decide(listOf("org.kysecurity.mail", "com.evil.shared"), { setOf(play) }, null))
    }

    @Test
    fun decide_debugDigestOnlyWhenSupplied() {
        val debug = "ab".repeat(32)
        assertNull(TrustedConsumers.decide(listOf("org.kysecurity.mail"), { setOf(debug) }, null))
        assertEquals("org.kysecurity.mail", TrustedConsumers.decide(listOf("org.kysecurity.mail"), { setOf(debug) }, debug)?.packageName)
    }

    @Test
    fun decide_refusesEmptyCertSet() {
        assertNull(TrustedConsumers.decide(listOf("org.kysecurity.mail"), { emptySet() }, play))
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./gradlew test --tests 'org.kysecurity.authenticator.signon.TrustedConsumersTest'`
Expected: FAIL, unresolved `TrustedConsumers`.

- [ ] **Step 3: Implement**

Obtain the real digests before writing them in: for the Play flavor the "App signing key certificate" SHA-256 from Play Console → Setup → App signing; for the GitHub APK the upload key, `keytool -list -v -keystore /home/yoshi/keystores/KyPost-Prod.jks -alias kypost-prod | grep SHA256`. Write them lowercase hex without colons. The F-Droid digest does not exist yet; leave the `.fdroid` entry out and record that in AGENTS.md (Task 7).

```kotlin
package org.kysecurity.authenticator.signon

import android.content.Context
import android.content.pm.PackageManager
import org.kysecurity.authenticator.BuildConfig
import java.security.MessageDigest

data class TrustedCaller(val packageName: String, val label: String)

/**
 * The apps allowed to ask for a KyIdentity sign-on token, by package and signing certificate.
 *
 * Package name alone proves nothing: anyone can build an APK named `org.kysecurity.mail`. The
 * SHA-256 of the signing certificate is what Android will not let an impostor forge. Every
 * package sharing the caller's UID must be pinned, because a shared UID reads the same
 * process memory.
 */
object TrustedConsumers {
    private data class Consumer(val label: String, val digests: Set<String>)

    // SHA-256 of the DER signing certificate, lowercase hex. Play App Signing key, then the
    // GitHub upload key. F-Droid signs with a key that does not exist until it builds KyPost.
    internal val PINS: Map<String, Set<String>> = mapOf(
        "org.kysecurity.mail" to setOf(
            "REPLACE_WITH_PLAY_APP_SIGNING_SHA256",
        ),
        "org.kysecurity.mail.github" to setOf(
            "REPLACE_WITH_UPLOAD_KEY_SHA256",
        ),
    )
    private val LABELS = mapOf(
        "org.kysecurity.mail" to "KyPost",
        "org.kysecurity.mail.github" to "KyPost",
    )

    fun isTrusted(context: Context, callerUid: Int): TrustedCaller? {
        val pm = context.packageManager
        val packages = pm.getPackagesForUid(callerUid)?.toList().orEmpty()
        val debugDigest = BuildConfig.DEBUG_CONSUMER_CERT.takeIf { BuildConfig.DEBUG && it.isNotBlank() }
        return decide(packages, { pkg -> signingDigests(pm, pkg) }, debugDigest)
    }

    internal fun decide(
        packagesForUid: List<String>,
        certDigestsFor: (String) -> Set<String>,
        extraDebugDigest: String?,
    ): TrustedCaller? {
        if (packagesForUid.isEmpty()) return null
        for (pkg in packagesForUid) {
            val pinned = PINS[pkg] ?: return null
            val allowed = if (extraDebugDigest != null) pinned + extraDebugDigest else pinned
            val actual = certDigestsFor(pkg)
            if (actual.isEmpty() || !allowed.containsAll(actual)) return null
        }
        val first = packagesForUid.first()
        return TrustedCaller(first, LABELS.getValue(first))
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

The test file's `first()` on the PIN set will read the placeholder string; that is fine for the unit test since `decide` compares strings. The placeholders MUST be replaced before merge; add `assertFalse(TrustedConsumers.PINS.values.flatten().any { it.startsWith("REPLACE") })` as a seventh test named `pins_areRealDigests` so CI fails until they are.

`app/build.gradle.kts` in `defaultConfig`:

```kotlin
        buildConfigField(
            "String",
            "DEBUG_CONSUMER_CERT",
            "\"${providers.gradleProperty("kyauthDebugConsumerCert").orNull.orEmpty()}\"",
        )
```

- [ ] **Step 4: Run tests**

Run: `./gradlew test --tests 'org.kysecurity.authenticator.signon.TrustedConsumersTest'`
Expected: all pass except `pins_areRealDigests` until the digests are filled in. Fill them in and re-run: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/build.gradle.kts app/src/main/java/org/kysecurity/authenticator/signon/TrustedConsumers.kt app/src/test/java/org/kysecurity/authenticator/signon/TrustedConsumersTest.kt
git commit -m "feat(signon): pin the apps allowed to request sign-on tokens"
```

---

### Task 3: `KyIdentityAccount` lifecycle + `canSignOn` from pairing

**Files:**
- Create: `app/src/main/java/org/kysecurity/authenticator/signon/KyIdentityAccount.kt`
- Modify: `app/src/main/java/org/kysecurity/authenticator/pairing/PairingStore.kt` (`PairedAccount` gains `canSignOn: Boolean = false`, persisted as `can_sign_on`)
- Modify: `app/src/main/java/org/kysecurity/authenticator/pairing/PairingClient.kt:46-53` (read `device.canSignOn`)
- Modify: `app/src/main/java/org/kysecurity/authenticator/MainActivity.kt:317` (after `store.save(account)`), `:2131` (unpair)
- Modify: `app/src/main/java/org/kysecurity/authenticator/security/SecurityWipe.kt` (step 1)
- Test: `app/src/test/java/org/kysecurity/authenticator/pairing/PairingClientTest.kt`

**Interfaces:**
- Produces: `object KyIdentityAccount { const val TYPE = "org.kysecurity.identity"; fun sync(context, account: PairedAccount?); fun remove(context); fun current(context): Account? }`. `sync` creates the account when `account?.canSignOn == true`, removes it otherwise. Idempotent.

- [ ] **Step 1: Write the failing parse test**

`PairingClient` builds `PairedAccount` from the response inline. Extract that into `internal fun PairingClient.parseRegistration(body: String, pairing: QrPairing, deviceName: String): PairedAccount` and test it:

```kotlin
    @Test
    fun parseRegistration_readsCanSignOn() {
        val client = PairingClient()
        val pairing = QrPairing(serverUrl = "https://id.example.com/", pairingToken = "t", username = "alice")
        val on = client.parseRegistration(
            """{"success":true,"deviceId":"dev-1","device":{"userId":"u1","canSignOn":true}}""", pairing, "Pixel",
        )
        assertEquals(true, on.canSignOn)
        assertEquals("u1", on.userId)
        val off = client.parseRegistration("""{"success":true,"deviceId":"dev-1","device":{"userId":"u1"}}""", pairing, "Pixel")
        assertEquals(false, off.canSignOn)
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `./gradlew test --tests 'org.kysecurity.authenticator.pairing.PairingClientTest'`
Expected: FAIL, unresolved `parseRegistration` / `canSignOn`.

- [ ] **Step 3: Implement store + client**

`PairingStore.kt`:

```kotlin
data class PairedAccount(
    val serverUrl: String,
    val deviceId: String,
    val deviceName: String,
    val username: String? = null,
    val userId: String? = null,
    val canSignOn: Boolean = false,
)
```

Read `can_sign_on` in `account()` with `preferences.getBoolean("can_sign_on", false)`, write it in `save`, remove it in `clear`.

`PairingClient.kt`: move the body-to-`PairedAccount` block into

```kotlin
    internal fun parseRegistration(body: String, pairing: QrPairing, deviceName: String): PairedAccount {
        val response = JSONObject(body.ifBlank { "{}" })
        val deviceId = response.optString("deviceId")
        require(deviceId.isNotBlank()) { "KyIdentity did not return a device ID" }
        val respDevice = response.optJSONObject("device")
        val userId = respDevice?.optString("userId")?.takeIf { it.isNotBlank() } ?: pairing.userId
        return PairedAccount(
            serverUrl = pairing.serverUrl.trimEnd('/'),
            deviceId = deviceId,
            deviceName = deviceName.trim(),
            username = pairing.username,
            userId = userId,
            canSignOn = respDevice?.optBoolean("canSignOn", false) ?: false,
        )
    }
```

and call it from `register` after the status/`success` check.

- [ ] **Step 4: Implement `KyIdentityAccount`**

```kotlin
package org.kysecurity.authenticator.signon

import android.accounts.Account
import android.accounts.AccountManager
import android.content.Context
import org.kysecurity.authenticator.pairing.PairedAccount

/** The system account KyAuth publishes for a paired device that may sign in to suite apps. */
object KyIdentityAccount {
    const val TYPE = "org.kysecurity.identity"
    const val KEY_SERVER_URL = "server_url"
    const val KEY_USER_ID = "user_id"
    const val KEY_DEVICE_ID = "device_id"

    fun current(context: Context): Account? =
        AccountManager.get(context).getAccountsByType(TYPE).firstOrNull()

    /** Makes the system account match the pairing: present iff the device can sign on. */
    fun sync(context: Context, account: PairedAccount?) {
        val am = AccountManager.get(context)
        val existing = am.getAccountsByType(TYPE)
        if (account == null || !account.canSignOn || account.userId.isNullOrBlank()) {
            existing.forEach { am.removeAccountExplicitly(it) }
            return
        }
        val name = account.username?.takeIf { it.isNotBlank() } ?: account.userId
        val wanted = Account(name, TYPE)
        existing.filter { it != wanted }.forEach { am.removeAccountExplicitly(it) }
        val data = android.os.Bundle().apply {
            putString(KEY_SERVER_URL, account.serverUrl)
            putString(KEY_USER_ID, account.userId)
            putString(KEY_DEVICE_ID, account.deviceId)
        }
        val visibility = TrustedConsumers.PINS.keys.associateWith { AccountManager.VISIBILITY_VISIBLE }
        if (existing.none { it == wanted }) {
            am.addAccountExplicitly(wanted, null, data, visibility)
        } else {
            am.setUserData(wanted, KEY_SERVER_URL, account.serverUrl)
            am.setUserData(wanted, KEY_USER_ID, account.userId)
            am.setUserData(wanted, KEY_DEVICE_ID, account.deviceId)
            visibility.forEach { (pkg, v) -> am.setAccountVisibility(wanted, pkg, v) }
        }
    }

    fun remove(context: Context) = sync(context, null)
}
```

`addAccountExplicitly(Account, String, Bundle, Map<String,Int>)` is API 26+; minSdk is 31. Make `PINS` `internal` (it is) and keep this object in the same module.

- [ ] **Step 5: Wire the call sites**

`MainActivity.kt:317` after `store.save(account)`:

```kotlin
                                    store.save(account)
                                    runCatching { KyIdentityAccount.sync(this@MainActivity, account) }
```

Unpair (`:2131`) after `store.clear()`:

```kotlin
                        store.clear()
                        runCatching { KyIdentityAccount.remove(this@MainActivity) }
```

`SecurityWipe.wipe` step 1:

```kotlin
        runCatching { org.kysecurity.authenticator.signon.KyIdentityAccount.remove(context) }
```

- [ ] **Step 6: Run tests and build**

Run: `./gradlew test assembleDebug`
Expected: PASS; build succeeds (the authenticator service does not exist yet, so `addAccountExplicitly` would throw at runtime until Task 4; unit tests do not touch it).

- [ ] **Step 7: Commit**

```bash
git add app/src/main/java/org/kysecurity/authenticator/signon/KyIdentityAccount.kt app/src/main/java/org/kysecurity/authenticator/pairing app/src/main/java/org/kysecurity/authenticator/MainActivity.kt app/src/main/java/org/kysecurity/authenticator/security/SecurityWipe.kt app/src/test/java/org/kysecurity/authenticator/pairing/PairingClientTest.kt
git commit -m "feat(signon): publish the KyIdentity system account for sign-on devices"
```

---

### Task 4: The authenticator and its service

**Files:**
- Create: `app/src/main/java/org/kysecurity/authenticator/signon/KyIdentityAuthenticator.kt`
- Create: `app/src/main/java/org/kysecurity/authenticator/signon/KyIdentityAuthenticatorService.kt`
- Create: `app/src/main/res/xml/kyidentity_authenticator.xml`
- Modify: `app/src/main/AndroidManifest.xml`
- Test: `app/src/test/java/org/kysecurity/authenticator/signon/SignOnRequestTest.kt`

**Interfaces:**
- Produces:
  - `sealed class SignOnRequest { data class Proceed(val caller: TrustedCaller, val clientId: String, val paired: PairedAccount) ; data class Refuse(val code: Int, val message: String) }`
  - `internal fun decideSignOn(caller: TrustedCaller?, authTokenType: String?, paired: PairedAccount?): SignOnRequest` (pure, tested)
  - `SignOnActivity` intent extras `EXTRA_CLIENT_ID`, `EXTRA_CALLER_LABEL`, `EXTRA_CALLER_PACKAGE`, plus `AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE`.

- [ ] **Step 1: Write the failing test**

```kotlin
package org.kysecurity.authenticator.signon

import android.accounts.AccountManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kysecurity.authenticator.pairing.PairedAccount

class SignOnRequestTest {
    private val caller = TrustedCaller("org.kysecurity.mail", "KyPost")
    private val paired = PairedAccount("https://id.example.com", "dev-1", "Pixel", "alice", "u1", canSignOn = true)

    @Test
    fun proceeds_forPinnedCallerValidTypeAndSignOnDevice() {
        val r = decideSignOn(caller, "kypost", paired)
        assertTrue(r is SignOnRequest.Proceed)
        assertEquals("kypost", (r as SignOnRequest.Proceed).clientId)
    }

    @Test
    fun refuses_unpinnedCaller() {
        val r = decideSignOn(null, "kypost", paired) as SignOnRequest.Refuse
        assertEquals(AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION, r.code)
    }

    @Test
    fun refuses_badClientId() {
        val r = decideSignOn(caller, "bad id!", paired) as SignOnRequest.Refuse
        assertEquals(AccountManager.ERROR_CODE_BAD_ARGUMENTS, r.code)
    }

    @Test
    fun refuses_whenNotPairedOrSignOnOff() {
        assertEquals(AccountManager.ERROR_CODE_BAD_REQUEST, (decideSignOn(caller, "kypost", null) as SignOnRequest.Refuse).code)
        assertEquals(AccountManager.ERROR_CODE_BAD_REQUEST, (decideSignOn(caller, "kypost", paired.copy(canSignOn = false)) as SignOnRequest.Refuse).code)
        assertEquals(AccountManager.ERROR_CODE_BAD_REQUEST, (decideSignOn(caller, "kypost", paired.copy(userId = null)) as SignOnRequest.Refuse).code)
    }
}
```

`android.accounts.AccountManager` constants are plain `int`s on the stub jar, so this runs without Robolectric (`unitTests.isReturnDefaultValues` is not required for static final fields).

- [ ] **Step 2: Run to verify it fails**

Run: `./gradlew test --tests 'org.kysecurity.authenticator.signon.SignOnRequestTest'`
Expected: FAIL, unresolved `decideSignOn`.

- [ ] **Step 3: Implement the decision and the authenticator**

`KyIdentityAuthenticator.kt`:

```kotlin
package org.kysecurity.authenticator.signon

import android.accounts.AbstractAccountAuthenticator
import android.accounts.Account
import android.accounts.AccountAuthenticatorResponse
import android.accounts.AccountManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import org.kysecurity.authenticator.MainActivity
import org.kysecurity.authenticator.pairing.PairedAccount
import org.kysecurity.authenticator.pairing.PairingStore

sealed class SignOnRequest {
    data class Proceed(val caller: TrustedCaller, val clientId: String, val paired: PairedAccount) : SignOnRequest()
    data class Refuse(val code: Int, val message: String) : SignOnRequest()
}

/** Everything that decides whether a token request may reach the prompt, with no Android state. */
internal fun decideSignOn(caller: TrustedCaller?, authTokenType: String?, paired: PairedAccount?): SignOnRequest {
    if (caller == null) return SignOnRequest.Refuse(AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION, "This app is not allowed to use KyIdentity sign-in")
    if (!DeviceAssertion.isValidClientId(authTokenType)) return SignOnRequest.Refuse(AccountManager.ERROR_CODE_BAD_ARGUMENTS, "Invalid client id")
    if (paired == null || !paired.canSignOn || paired.userId.isNullOrBlank()) {
        return SignOnRequest.Refuse(AccountManager.ERROR_CODE_BAD_REQUEST, "This device is not enabled for sign-in. Pair KyAuth again or enable sign-in on the KyIdentity devices page.")
    }
    return SignOnRequest.Proceed(caller, authTokenType!!, paired)
}

/**
 * Account authenticator for `org.kysecurity.identity`. `customTokens` is on, so the system never
 * caches what this returns and every request arrives with the caller's UID.
 */
class KyIdentityAuthenticator(private val context: Context) : AbstractAccountAuthenticator(context) {

    override fun addAccount(
        response: AccountAuthenticatorResponse?,
        accountType: String?,
        authTokenType: String?,
        requiredFeatures: Array<out String>?,
        options: Bundle?,
    ): Bundle {
        val intent = Intent(context, MainActivity::class.java)
            .putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response)
        return Bundle().apply { putParcelable(AccountManager.KEY_INTENT, intent) }
    }

    override fun getAuthToken(
        response: AccountAuthenticatorResponse?,
        account: Account?,
        authTokenType: String?,
        options: Bundle?,
    ): Bundle {
        val uid = options?.getInt(AccountManager.KEY_CALLER_UID, -1) ?: -1
        val caller = if (uid > 0) TrustedConsumers.isTrusted(context, uid) else null
        val paired = runCatching { PairingStore(context).account() }.getOrNull()
        return when (val decision = decideSignOn(caller, authTokenType, paired)) {
            is SignOnRequest.Refuse -> {
                if (paired == null || !paired.canSignOn) runCatching { KyIdentityAccount.sync(context, paired) }
                error(decision.code, decision.message)
            }
            is SignOnRequest.Proceed -> {
                val intent = Intent(context, SignOnActivity::class.java)
                    .putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response)
                    .putExtra(SignOnActivity.EXTRA_CLIENT_ID, decision.clientId)
                    .putExtra(SignOnActivity.EXTRA_CALLER_LABEL, decision.caller.label)
                    .putExtra(SignOnActivity.EXTRA_CALLER_PACKAGE, decision.caller.packageName)
                Bundle().apply { putParcelable(AccountManager.KEY_INTENT, intent) }
            }
        }
    }

    override fun getAuthTokenLabel(authTokenType: String?): String = "KyIdentity sign-in"

    override fun hasFeatures(response: AccountAuthenticatorResponse?, account: Account?, features: Array<out String>?): Bundle =
        Bundle().apply { putBoolean(AccountManager.KEY_BOOLEAN_RESULT, features?.all { it == "signon" } == true) }

    override fun getAccountRemovalAllowed(response: AccountAuthenticatorResponse?, account: Account?): Bundle =
        Bundle().apply { putBoolean(AccountManager.KEY_BOOLEAN_RESULT, true) }

    override fun editProperties(response: AccountAuthenticatorResponse?, accountType: String?): Bundle = error(AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION, "Not supported")
    override fun confirmCredentials(response: AccountAuthenticatorResponse?, account: Account?, options: Bundle?): Bundle? = null
    override fun updateCredentials(response: AccountAuthenticatorResponse?, account: Account?, authTokenType: String?, options: Bundle?): Bundle? = null

    private fun error(code: Int, message: String) = Bundle().apply {
        putInt(AccountManager.KEY_ERROR_CODE, code)
        putString(AccountManager.KEY_ERROR_MESSAGE, message)
    }
}
```

`KyIdentityAuthenticatorService.kt`:

```kotlin
package org.kysecurity.authenticator.signon

import android.app.Service
import android.content.Intent
import android.os.IBinder

class KyIdentityAuthenticatorService : Service() {
    private val authenticator by lazy { KyIdentityAuthenticator(this) }
    override fun onBind(intent: Intent?): IBinder? = authenticator.iBinder
}
```

`res/xml/kyidentity_authenticator.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<account-authenticator xmlns:android="http://schemas.android.com/apk/res/android"
    android:accountType="org.kysecurity.identity"
    android:icon="@mipmap/ic_launcher"
    android:smallIcon="@mipmap/ic_launcher"
    android:label="@string/signon_account_label"
    android:customTokens="true" />
```

Manifest, inside `<application>`:

```xml
        <service
            android:name=".signon.KyIdentityAuthenticatorService"
            android:exported="true">
            <intent-filter>
                <action android:name="android.accounts.AccountAuthenticator" />
            </intent-filter>
            <meta-data
                android:name="android.accounts.AccountAuthenticator"
                android:resource="@xml/kyidentity_authenticator" />
        </service>
        <activity
            android:name=".signon.SignOnActivity"
            android:exported="false"
            android:excludeFromRecents="true"
            android:theme="@style/Theme.KyAuth" />
```

`exported="true"` is required for the system to bind the authenticator. `strings.xml`: `<string name="signon_account_label">KyIdentity</string>`.

`SignOnActivity` is created in Task 5; add an empty class stub now so this compiles:

```kotlin
package org.kysecurity.authenticator.signon

import androidx.appcompat.app.AppCompatActivity

class SignOnActivity : AppCompatActivity() {
    companion object {
        const val EXTRA_CLIENT_ID = "client_id"
        const val EXTRA_CALLER_LABEL = "caller_label"
        const val EXTRA_CALLER_PACKAGE = "caller_package"
    }
}
```

- [ ] **Step 4: Run tests and build**

Run: `./gradlew test assembleDebug lintDebug`
Expected: PASS, build succeeds.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/AndroidManifest.xml app/src/main/res/xml/kyidentity_authenticator.xml app/src/main/res/values/strings.xml app/src/main/java/org/kysecurity/authenticator/signon app/src/test/java/org/kysecurity/authenticator/signon/SignOnRequestTest.kt
git commit -m "feat(signon): KyIdentity account authenticator"
```

---

### Task 5: `TokenClient` — the grant request

**Files:**
- Create: `app/src/main/java/org/kysecurity/authenticator/signon/TokenClient.kt`
- Test: `app/src/test/java/org/kysecurity/authenticator/signon/TokenClientTest.kt`

**Interfaces:**
- Produces:
  - `sealed class TokenResult { data class Success(val idToken: String, val expiresAtEpochSeconds: Long); data class Failure(val userMessage: String, val signOnDisabled: Boolean) }`
  - `class TokenClient { fun redeem(serverUrl: String, clientId: String, assertion: String): TokenResult; internal fun formBody(clientId, assertion): String; internal fun parse(status: Int, body: String, nowEpochSeconds: Long): TokenResult }`

- [ ] **Step 1: Write the failing tests**

```kotlin
package org.kysecurity.authenticator.signon

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TokenClientTest {
    private val client = TokenClient()

    @Test
    fun formBody_isJwtBearerGrant() {
        val body = client.formBody("kypost", "h.c.s")
        assertEquals("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=h.c.s&client_id=kypost", body)
    }

    @Test
    fun parse_success() {
        val r = client.parse(200, """{"access_token":"a","token_type":"Bearer","expires_in":900,"id_token":"eyJ.x.y"}""", 1000) as TokenResult.Success
        assertEquals("eyJ.x.y", r.idToken)
        assertEquals(1900L, r.expiresAtEpochSeconds)
    }

    @Test
    fun parse_missingIdToken() {
        val r = client.parse(200, """{"access_token":"a"}""", 1000)
        assertTrue(r is TokenResult.Failure)
    }

    @Test
    fun parse_signOnDisabled() {
        val r = client.parse(400, """{"error":"invalid_grant","error_description":"device_signon_disabled"}""", 1000) as TokenResult.Failure
        assertTrue(r.signOnDisabled)
        assertTrue(r.userMessage.contains("KyIdentity devices page"))
    }

    @Test
    fun parse_otherErrorsAreGeneric() {
        val r = client.parse(400, """{"error":"invalid_grant","error_description":"The device assertion is invalid"}""", 1000) as TokenResult.Failure
        assertEquals(false, r.signOnDisabled)
        val rl = client.parse(429, "", 1000) as TokenResult.Failure
        assertTrue(rl.userMessage.contains("Try again"))
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `./gradlew test --tests 'org.kysecurity.authenticator.signon.TokenClientTest'`
Expected: FAIL, unresolved `TokenClient`.

- [ ] **Step 3: Implement**

```kotlin
package org.kysecurity.authenticator.signon

import org.json.JSONObject
import org.kysecurity.authenticator.pairing.PairingEndpoint
import java.net.HttpURLConnection
import java.net.URLEncoder

sealed class TokenResult {
    data class Success(val idToken: String, val expiresAtEpochSeconds: Long) : TokenResult()
    data class Failure(val userMessage: String, val signOnDisabled: Boolean = false) : TokenResult()
}

/** Redeems a device assertion at KyIdentity's token endpoint. The ID token is returned, never stored. */
class TokenClient {
    fun redeem(serverUrl: String, clientId: String, assertion: String): TokenResult {
        val endpoint = PairingEndpoint.validatedServerUri(serverUrl).resolve("/oauth/token")
        val connection = (endpoint.toURL().openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 10_000
            readTimeout = 10_000
            doOutput = true
            instanceFollowRedirects = false
            setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
            setRequestProperty("Accept", "application/json")
        }
        return try {
            connection.outputStream.bufferedWriter(Charsets.UTF_8).use { it.write(formBody(clientId, assertion)) }
            val body = (if (connection.responseCode in 200..299) connection.inputStream else connection.errorStream)
                ?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
            parse(connection.responseCode, body, System.currentTimeMillis() / 1000)
        } catch (e: Exception) {
            TokenResult.Failure("Could not reach KyIdentity: ${e.message ?: "network error"}")
        } finally {
            connection.disconnect()
        }
    }

    internal fun formBody(clientId: String, assertion: String): String = listOf(
        "grant_type" to "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion" to assertion,
        "client_id" to clientId,
    ).joinToString("&") { (k, v) -> k + "=" + URLEncoder.encode(v, "UTF-8") }

    internal fun parse(status: Int, body: String, nowEpochSeconds: Long): TokenResult {
        val json = runCatching { JSONObject(body.ifBlank { "{}" }) }.getOrElse { JSONObject() }
        if (status == 429) return TokenResult.Failure("KyIdentity is busy. Try again in a minute.")
        if (status !in 200..299) {
            val description = json.optString("error_description")
            if (description == "device_signon_disabled") {
                return TokenResult.Failure(
                    "Sign-in from this phone is turned off. Enable it for this device on the KyIdentity devices page.",
                    signOnDisabled = true,
                )
            }
            return TokenResult.Failure("KyIdentity refused the sign-in ($status).")
        }
        val idToken = json.optString("id_token")
        if (idToken.isBlank()) return TokenResult.Failure("KyIdentity returned no identity token.")
        val expiresIn = json.optLong("expires_in", 60)
        return TokenResult.Success(idToken, nowEpochSeconds + expiresIn)
    }
}
```

Look at `PairingEndpoint.kt` for the function that validates the server URL scheme (HTTPS, loopback in debug) and use its real name in place of `validatedServerUri`; if it only validates as a side effect of building the registration endpoint, extract the validation into a small `internal fun serverUri(serverUrl: String): URI` there and call it from both places.

- [ ] **Step 4: Run tests**

Run: `./gradlew test --tests 'org.kysecurity.authenticator.signon.TokenClientTest'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/org/kysecurity/authenticator/signon/TokenClient.kt app/src/test/java/org/kysecurity/authenticator/signon/TokenClientTest.kt app/src/main/java/org/kysecurity/authenticator/pairing/PairingEndpoint.kt
git commit -m "feat(signon): token client for the jwt-bearer grant"
```

---

### Task 6: `SignOnActivity` — prompt, sign, deliver

**Files:**
- Modify: `app/src/main/java/org/kysecurity/authenticator/signon/SignOnActivity.kt` (replace stub)
- Modify: `app/src/main/res/values/strings.xml`

**Interfaces:**
- Consumes: `DeviceAssertion`, `TokenClient`, `DeviceSigningKey.initSignature()`, `VaultUnlockPrompt.showForSignature`, `PairingStore`, `KyIdentityAccount`.

- [ ] **Step 1: Implement**

```kotlin
package org.kysecurity.authenticator.signon

import android.accounts.AccountAuthenticatorResponse
import android.accounts.AccountManager
import android.os.Bundle
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import org.kysecurity.authenticator.BuildConfig
import org.kysecurity.authenticator.ThemeManager
import org.kysecurity.authenticator.pairing.DeviceSigningKey
import org.kysecurity.authenticator.pairing.PairingStore
import org.kysecurity.authenticator.parcelable
import org.kysecurity.authenticator.security.VaultUnlockPrompt
import java.net.URI
import java.util.UUID

/**
 * "KyPost wants to sign in as alice". One biometric, one assertion, one token, delivered to the
 * caller through the authenticator response. Touches no vault key.
 */
class SignOnActivity : AppCompatActivity() {
    companion object {
        const val EXTRA_CLIENT_ID = "client_id"
        const val EXTRA_CALLER_LABEL = "caller_label"
        const val EXTRA_CALLER_PACKAGE = "caller_package"
    }

    private var response: AccountAuthenticatorResponse? = null
    private var delivered = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!BuildConfig.ALLOW_SCREENSHOTS) window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        ThemeManager.apply(this)
        response = intent.parcelable(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE)
        val clientId = intent.getStringExtra(EXTRA_CLIENT_ID)
        val callerLabel = intent.getStringExtra(EXTRA_CALLER_LABEL)
        val paired = runCatching { PairingStore(this).account() }.getOrNull()
        val decision = decideSignOn(
            caller = callerLabel?.let { TrustedCaller(intent.getStringExtra(EXTRA_CALLER_PACKAGE).orEmpty(), it) },
            authTokenType = clientId,
            paired = paired,
        )
        if (decision !is SignOnRequest.Proceed) {
            fail((decision as SignOnRequest.Refuse).code, decision.message)
            return
        }
        render(decision)
    }

    private fun render(request: SignOnRequest.Proceed) {
        val host = runCatching { URI(request.paired.serverUrl).host }.getOrNull() ?: request.paired.serverUrl
        val who = request.paired.username ?: request.paired.userId
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 96, 48, 48)
            setBackgroundColor(ThemeManager.color(context, org.kysecurity.authenticator.R.color.ky_background))
        }
        root.addView(TextView(this).apply {
            text = getString(org.kysecurity.authenticator.R.string.signon_prompt, request.caller.label, who, host)
            textSize = 18f
            setTextColor(ThemeManager.color(context, org.kysecurity.authenticator.R.color.ky_text))
        })
        root.addView(Button(this).apply {
            text = getString(org.kysecurity.authenticator.R.string.signon_approve)
            setOnClickListener { isEnabled = false; approve(request) }
        })
        root.addView(Button(this).apply {
            text = getString(org.kysecurity.authenticator.R.string.signon_deny)
            setOnClickListener { fail(AccountManager.ERROR_CODE_CANCELED, "Sign-in denied") }
        })
        setContentView(root)
    }

    private fun approve(request: SignOnRequest.Proceed) {
        val signature = runCatching { DeviceSigningKey.initSignature() }.getOrElse {
            fail(AccountManager.ERROR_CODE_REMOTE_EXCEPTION, "The device key is unavailable. Re-pair KyAuth.")
            return
        }
        VaultUnlockPrompt.showForSignature(
            activity = this,
            subtitle = getString(org.kysecurity.authenticator.R.string.signon_biometric_subtitle, request.caller.label),
            signature = signature,
            onAuthenticated = { authed -> signAndRedeem(request, authed) },
            onFailed = { fail(AccountManager.ERROR_CODE_CANCELED, it) },
        )
    }

    private fun signAndRedeem(request: SignOnRequest.Proceed, authed: java.security.Signature) {
        val paired = request.paired
        val input = DeviceAssertion.signingInput(
            deviceId = paired.deviceId,
            userId = paired.userId!!,
            serverUrl = paired.serverUrl,
            clientId = request.clientId,
            nowEpochSeconds = System.currentTimeMillis() / 1000,
            jti = UUID.randomUUID().toString(),
        )
        val der = runCatching { authed.update(input.toByteArray()); authed.sign() }.getOrElse {
            fail(AccountManager.ERROR_CODE_REMOTE_EXCEPTION, "Could not sign the sign-in request")
            return
        }
        val assertion = DeviceAssertion.compact(input, DeviceAssertion.derToRaw(der))
        Thread {
            val result = TokenClient().redeem(paired.serverUrl, request.clientId, assertion)
            runOnUiThread {
                when (result) {
                    is TokenResult.Success -> deliver(result)
                    is TokenResult.Failure -> {
                        if (result.signOnDisabled) runCatching { PairingStore(this).save(paired.copy(canSignOn = false)); KyIdentityAccount.remove(this) }
                        fail(AccountManager.ERROR_CODE_REMOTE_EXCEPTION, result.userMessage)
                    }
                }
            }
        }.start()
    }

    private fun deliver(result: TokenResult.Success) {
        val bundle = Bundle().apply {
            putString(AccountManager.KEY_ACCOUNT_NAME, KyIdentityAccount.current(this@SignOnActivity)?.name)
            putString(AccountManager.KEY_ACCOUNT_TYPE, KyIdentityAccount.TYPE)
            putString(AccountManager.KEY_AUTHTOKEN, result.idToken)
            putLong(AccountManager.KEY_CUSTOM_TOKEN_EXPIRY, result.expiresAtEpochSeconds * 1000)
        }
        delivered = true
        response?.onResult(bundle)
        finish()
    }

    private fun fail(code: Int, message: String) {
        if (!delivered) {
            delivered = true
            response?.onError(code, message)
        }
        finish()
    }

    override fun onDestroy() {
        if (!delivered) response?.onError(AccountManager.ERROR_CODE_CANCELED, "Sign-in cancelled")
        super.onDestroy()
    }
}
```

Check `ThemeManager` for the real apply/colour helpers (`grep -n "fun apply\|fun color" app/src/main/java/org/kysecurity/authenticator/ThemeManager.kt`) and `parcelable` (`grep -rn "fun <.*> Intent.parcelable" app/src/main/java`). Use `primaryButton`-style backgrounds from `UiComponents.kt` only if they are usable outside `MainActivity`; those helpers are `MainActivity` extensions, so plain `Button`s with `roundedButtonBackground`-equivalent drawables built inline are acceptable here.

`strings.xml`:

```xml
    <string name="signon_prompt">%1$s wants to sign in as %2$s at %3$s.</string>
    <string name="signon_approve">Approve sign-in</string>
    <string name="signon_deny">Deny</string>
    <string name="signon_biometric_subtitle">Sign in to %1$s</string>
```

- [ ] **Step 2: Build, lint, and compile device tests**

Run: `./gradlew test lintDebug assembleDebug compileDebugAndroidTestSources`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/org/kysecurity/authenticator/signon/SignOnActivity.kt app/src/main/res/values/strings.xml
git commit -m "feat(signon): sign-in prompt that signs and redeems the device assertion"
```

---

### Task 7: Settings row, AGENTS.md, device verification checklist

**Files:**
- Modify: `app/src/main/java/org/kysecurity/authenticator/MainActivity.kt` (settings account section, ~2100-2140)
- Modify: `AGENTS.md`

- [ ] **Step 1: Settings row**

In the account section of Settings (before `btnUnpair`), add a status line and a repair action:

```kotlin
        val signOnState = when {
            account?.canSignOn != true -> "Suite app sign-in: off for this device (enable it on the KyIdentity devices page, then pair again)"
            KyIdentityAccount.current(this) != null -> "Suite app sign-in: on. KyPost and other suite apps can use this account."
            else -> "Suite app sign-in: account missing"
        }
        accountSection.addView(message(signOnState))
        if (account?.canSignOn == true && KyIdentityAccount.current(this) == null) {
            accountSection.addView(secondaryButton("Restore system account").apply {
                setOnClickListener { runCatching { KyIdentityAccount.sync(this@MainActivity, account) }; renderContent() }
            }, fullWidthParams())
        }
```

`account` is whatever local the settings renderer already holds for `store.account()`; match its name.

- [ ] **Step 2: AGENTS.md**

Under "Current product contract" add:

- KyAuth is the Android account authenticator for `org.kysecurity.identity` (`signon/`). The account exists iff the paired device has KyIdentity's `canSignOn`; its user data is `server_url`, `user_id`, `device_id`, never a secret. `customTokens` is on: the system caches nothing and every `getAuthToken` carries the caller UID. `TrustedConsumers` pins caller package + signing-certificate SHA-256 and fails closed; a shared UID must be fully pinned. `authTokenType` is the consumer server's KyIdentity `client_id`. `SignOnActivity` shows who is asking, takes one biometric through `VaultUnlockPrompt.showForSignature` on `DeviceSigningKey` (no vault key involved, so it works while locked), signs an RFC 7523 assertion (`DeviceAssertion`), redeems it at `/oauth/token` (`TokenClient`) and returns the ID token once. A `device_signon_disabled` answer clears the local flag and removes the account.

Under "Project layout" add `signon/`: assertion builder, consumer pins, account lifecycle, authenticator, sign-in activity, token client.

Under "Outstanding security work" add:

- **Consumer pins.** `TrustedConsumers` holds Play App Signing and upload-key digests for KyPost. The F-Droid build's digest cannot be pinned until F-Droid publishes it. Debug builds accept `kyauthDebugConsumerCert`.
- **Sign-on device verification.** Unverified on hardware: the full `SignOnActivity` prompt; cancelling the biometric returns `ERROR_CODE_CANCELED` without a network call; account visibility for a consumer installed after the account was created (`setAccountVisibility` by package name before install); Settings → Accounts removal followed by "Restore system account". Do not claim these until observed.

- [ ] **Step 3: Full verification and commit**

Run: `./gradlew test lintDebug assembleDebug compileDebugAndroidTestSources`
Expected: PASS.

```bash
git add AGENTS.md app/src/main/java/org/kysecurity/authenticator/MainActivity.kt
git commit -m "docs: sign-on contract and settings status"
```
