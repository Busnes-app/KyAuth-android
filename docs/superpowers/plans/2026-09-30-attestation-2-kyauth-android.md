# KyAuth attested device key Implementation Plan (2 of 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** At pairing, KyAuth generates a fresh device key with a server-derivable attestation challenge, uploads the attestation chain, and shows the attested level the server recorded.

**Architecture:** A pure `AttestationChallenge` derivation; `DeviceSigningKey.regenerate(challenge)` (delete alias, StrongBox-first generation with `setAttestationChallenge`, TEE fallback, no-challenge fallback) returning the chain; `PairingClient` sends `attestation` and reads `device.attestedLevel`/`bootState`; `PairedAccount` stores them; Settings renders them. Sign-on code is untouched (it reads only `userId`, `canSignOn`, `serverUrl`, `deviceId`, `username`).

**Tech Stack:** Kotlin, `android.security.keystore`, `java.security.KeyStore`, JUnit 4 (JVM, no Robolectric), AndroidJUnit4 instrumented tests.

**Spec:** `docs/superpowers/specs/2026-09-30-device-signon-attestation-design.md`, sections 1 and 6.

**Repo:** `/home/yoshi/git/busnes.app/kyauth-android`, branch `feature/attested-device-key` from `main` (KyAuth #15 should be merged first; if not, branch from `feature/signon-origin-binding`).

## Global Constraints

- Alias stays `kysignon-device-signing-v1`. Key parameters stay: EC secp256r1, SHA-256, `PURPOSE_SIGN or PURPOSE_VERIFY`, `setUserAuthenticationRequired(true)`, `setUserAuthenticationParameters(0, BIOMETRIC_STRONG or DEVICE_CREDENTIAL)`.
- Challenge = `SHA-256("kyidentity-attest-v1|" + credential)` where credential is `pairingToken` when present, else `userId + "|" + pinCode`. 32 bytes. Identical on the server.
- Every pairing generates a NEW key (delete alias first). StrongBox first, TEE on any failure, then no-challenge generation on any failure; never fail pairing because of attestation.
- Registration request field `attestation`: JSON array of base64 (standard, padded) DER certificates, leaf first, from `KeyStore.getCertificateChain(alias)`; omitted when no chain.
- Registration response: `device.attestedLevel` ∈ `none|tee|strongbox` (missing → `none`), `device.bootState` string (missing → `unknown`).
- `PairedAccount` gains `attestedLevel: String = "none"`, `bootState: String = "unknown"`, persisted as `attested_level`, `boot_state`; `clear()` removes them.
- Settings copy: "Attested: StrongBox", "Attested: TEE", or "Not attested. Pair again to attest this phone."
- Verification: `./gradlew test lintDebug assembleDebug compileDebugAndroidTestSources`.

## Review Focus

1. A device whose keystore throws on `setAttestationChallenge` (no attestation support) must still pair, with no `attestation` field. Pinned in Task 2 by the fallback path structure plus an instrumented test that a generated key on the emulator yields a chain (software) and pairing JSON still builds.
2. Re-pairing a phone that previously paired must not leave the old key: `regenerate` deletes the alias before generating. Pinned in Task 2 (instrumented: two `regenerate` calls yield different public keys).
3. A pairing whose QR carries both a token and a PIN uses the token for the challenge (server does the same). Pinned in Task 1.
4. A response without `device.attestedLevel` (older server) reads as `none`, never crashes. Pinned in Task 3.
5. `initSignature()`/`publicKeyBase64()` lazy generation must not silently create an unattested key mid-pairing: pairing passes the freshly regenerated public key explicitly. Pinned in Task 4 by passing `publicKeyBase64` from `regenerate`.

---

### Task 1: `AttestationChallenge` — pure derivation

**Files:**
- Create: `app/src/main/java/org/kysecurity/authenticator/pairing/AttestationChallenge.kt`
- Test: `app/src/test/java/org/kysecurity/authenticator/pairing/AttestationChallengeTest.kt`

**Interfaces:**
- Produces: `object AttestationChallenge { fun forPairing(pairing: QrPairing): ByteArray; internal fun credential(pairing: QrPairing): String }`.

- [ ] **Step 1: Write the failing test**

```kotlin
package org.kysecurity.authenticator.pairing

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.security.MessageDigest

class AttestationChallengeTest {
    private fun sha(s: String) = MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))

    @Test
    fun tokenPath_usesPairingToken() {
        val p = QrPairing(serverUrl = "https://id.example", pairingToken = "abc123")
        assertEquals("abc123", AttestationChallenge.credential(p))
        assertArrayEquals(sha("kyidentity-attest-v1|abc123"), AttestationChallenge.forPairing(p))
    }

    @Test
    fun pinPath_usesUserIdAndPin() {
        val p = QrPairing(serverUrl = "https://id.example", pinCode = "123456", userId = "u1")
        assertEquals("u1|123456", AttestationChallenge.credential(p))
        assertArrayEquals(sha("kyidentity-attest-v1|u1|123456"), AttestationChallenge.forPairing(p))
    }

    @Test
    fun tokenWinsWhenBothPresent() {
        val p = QrPairing(serverUrl = "https://id.example", pairingToken = "tok", pinCode = "123456", userId = "u1")
        assertEquals("tok", AttestationChallenge.credential(p))
    }

    @Test
    fun challengeIsThirtyTwoBytes() {
        assertEquals(32, AttestationChallenge.forPairing(QrPairing(serverUrl = "https://x", pairingToken = "t")).size)
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./gradlew testDebugUnitTest --offline --tests 'org.kysecurity.authenticator.pairing.AttestationChallengeTest'`
Expected: FAIL, unresolved reference `AttestationChallenge`.

- [ ] **Step 3: Implement**

```kotlin
package org.kysecurity.authenticator.pairing

import java.security.MessageDigest

/**
 * The attestation challenge for a pairing. Derived from the credential the phone presents, so
 * KyIdentity recomputes it from the registration request without another round trip.
 */
object AttestationChallenge {
    private const val PREFIX = "kyidentity-attest-v1|"

    internal fun credential(pairing: QrPairing): String =
        pairing.pairingToken?.takeIf { it.isNotBlank() } ?: "${pairing.userId}|${pairing.pinCode}"

    fun forPairing(pairing: QrPairing): ByteArray =
        MessageDigest.getInstance("SHA-256").digest((PREFIX + credential(pairing)).toByteArray(Charsets.UTF_8))
}
```

- [ ] **Step 4: Run tests**

Run: `./gradlew testDebugUnitTest --offline --tests 'org.kysecurity.authenticator.pairing.AttestationChallengeTest'`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/org/kysecurity/authenticator/pairing/AttestationChallenge.kt app/src/test/java/org/kysecurity/authenticator/pairing/AttestationChallengeTest.kt
git commit -m "feat(pairing): derive the attestation challenge from the pairing credential"
```

---

### Task 2: `DeviceSigningKey.regenerate(challenge)` with the chain

**Files:**
- Modify: `app/src/main/java/org/kysecurity/authenticator/pairing/DeviceSigningKey.kt`
- Test: `app/src/androidTest/java/org/kysecurity/authenticator/pairing/DeviceSigningKeyAttestationTest.kt` (new, instrumented)

**Interfaces:**
- Produces: `data class GeneratedDeviceKey(val publicKeyBase64: String, val attestationChain: List<String>, val strongBoxAttempted: Boolean)` and `fun DeviceSigningKey.regenerate(challenge: ByteArray): GeneratedDeviceKey`. `attestationChain` is base64 DER, leaf first, empty when the key was generated without a challenge or the keystore returned no chain.

- [ ] **Step 1: Write the failing instrumented test**

```kotlin
package org.kysecurity.authenticator.pairing

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

@RunWith(AndroidJUnit4::class)
class DeviceSigningKeyAttestationTest {
    @After fun tearDown() = DeviceSigningKey.deleteKey()

    @Test
    fun regenerate_returnsChainWhoseLeafMatchesPublicKey() {
        val challenge = ByteArray(32) { it.toByte() }
        val generated = DeviceSigningKey.regenerate(challenge)
        // Emulators ship software KeyMint: the chain may be software-rooted, but it must still exist and
        // its leaf must carry the generated public key. The server grades a software chain `none`.
        assertTrue("chain expected on any KeyMint device", generated.attestationChain.isNotEmpty())
        val cf = CertificateFactory.getInstance("X.509")
        val leaf = cf.generateCertificate(ByteArrayInputStream(Base64.getDecoder().decode(generated.attestationChain[0]))) as X509Certificate
        assertEquals(generated.publicKeyBase64, Base64.getEncoder().encodeToString(leaf.publicKey.encoded))
        assertEquals(generated.publicKeyBase64, DeviceSigningKey.publicKeyBase64())
    }

    @Test
    fun regenerate_replacesThePreviousKey() {
        val a = DeviceSigningKey.regenerate(ByteArray(32) { 1 })
        val b = DeviceSigningKey.regenerate(ByteArray(32) { 2 })
        assertNotEquals(a.publicKeyBase64, b.publicKeyBase64)
        assertEquals(b.publicKeyBase64, DeviceSigningKey.publicKeyBase64())
    }
}
```

- [ ] **Step 2: Verify it fails to compile**

Run: `./gradlew compileDebugAndroidTestSources --offline`
Expected: FAIL, unresolved `regenerate`.

- [ ] **Step 3: Implement**

In `DeviceSigningKey.kt` add, keeping every existing member unchanged:

```kotlin
data class GeneratedDeviceKey(
    val publicKeyBase64: String,
    /** Base64 DER certificates, leaf first; empty when the keystore attested nothing. */
    val attestationChain: List<String>,
    val strongBoxAttempted: Boolean,
)
```

and inside the object:

```kotlin
    /**
     * Creates a fresh device key for one pairing. The attestation challenge is fixed at generation, so
     * the old key is deleted first; a re-pair therefore rotates the key. StrongBox first, TEE on any
     * failure, and a plain key when the device cannot attest at all. Pairing never fails here.
     */
    fun regenerate(challenge: ByteArray): GeneratedDeviceKey {
        testKeyPair?.let { return GeneratedDeviceKey(Base64.getEncoder().encodeToString(it.public.encoded), emptyList(), false) }
        deleteKey()
        val strongBox = runCatching { generateWith(challenge, strongBox = true) }.isSuccess
        if (!strongBox) {
            val tee = runCatching { generateWith(challenge, strongBox = false) }.isSuccess
            if (!tee) {
                deleteKey()
                generate() // no challenge: the device cannot attest; the server grades it none
            }
        }
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        val chain = runCatching { keyStore.getCertificateChain(ALIAS)?.toList().orEmpty() }.getOrDefault(emptyList())
        val publicKey = keyStore.getCertificate(ALIAS)?.publicKey ?: generate().public
        return GeneratedDeviceKey(
            publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.encoded),
            attestationChain = chain.map { Base64.getEncoder().encodeToString(it.encoded) },
            strongBoxAttempted = strongBox,
        )
    }

    private fun generateWith(challenge: ByteArray, strongBox: Boolean) {
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE).apply {
            initialize(
                KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(0, authenticationTypes())
                    .setAttestationChallenge(challenge)
                    .setIsStrongBoxBacked(strongBox)
                    .build(),
            )
        }.generateKeyPair()
    }
```

Note the failure semantics: `generateWith` throwing after partially creating an entry is handled by the `deleteKey()` before the no-challenge fallback. A chain of one self-signed certificate is still returned (the server grades it `none`).

- [ ] **Step 4: Compile and run on the emulator if available**

Run: `./gradlew compileDebugAndroidTestSources assembleDebug lintDebug --offline`
Expected: BUILD SUCCESSFUL. If an emulator is running: `./gradlew connectedDebugAndroidTest --offline --tests '*DeviceSigningKeyAttestationTest'` → both tests PASS (software chain on the emulator). Record in the report whether the emulator run happened.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/org/kysecurity/authenticator/pairing/DeviceSigningKey.kt app/src/androidTest/java/org/kysecurity/authenticator/pairing/DeviceSigningKeyAttestationTest.kt
git commit -m "feat(pairing): regenerate the device key per pairing with an attestation challenge"
```

---

### Task 3: `PairingClient` sends the chain and reads the level; `PairedAccount` stores it

**Files:**
- Modify: `app/src/main/java/org/kysecurity/authenticator/pairing/PairingClient.kt` (`register` signature, `registrationRequestJson`, `parseRegistration`)
- Modify: `app/src/main/java/org/kysecurity/authenticator/pairing/PairingStore.kt`
- Test: `app/src/test/java/org/kysecurity/authenticator/pairing/PairingClientTest.kt`

**Interfaces:**
- Produces: `PairingClient.register(pairing, deviceName, deviceIdentifier, pushToken, publicKeyBase64, attestationChain: List<String> = emptyList())`; `registrationRequestJson(..., attestationChain)`; `PairedAccount.attestedLevel`, `.bootState`.

- [ ] **Step 1: Write the failing tests**

Add to `PairingClientTest`:

```kotlin
    @Test
    fun registrationRequestJson_includesAttestationChainWhenPresent() {
        val with = JSONObject(PairingClient().registrationRequestJson(
            pairing = QrPairing(serverUrl = "https://signin.example.com", pairingToken = "pair-token"),
            deviceName = "Pixel", deviceIdentifier = "i", pushToken = "fcm", publicKeyBase64 = "pk",
            attestationChain = listOf("leafB64", "intB64", "rootB64"),
        ))
        val arr = with.getJSONArray("attestation")
        assertEquals(3, arr.length()); assertEquals("leafB64", arr.getString(0))
        val without = JSONObject(PairingClient().registrationRequestJson(
            pairing = QrPairing(serverUrl = "https://signin.example.com", pairingToken = "pair-token"),
            deviceName = "Pixel", deviceIdentifier = "i", pushToken = "fcm", publicKeyBase64 = "pk",
            attestationChain = emptyList(),
        ))
        assertEquals(false, without.has("attestation"))
    }

    @Test
    fun parseRegistration_readsAttestedLevelAndBootState() {
        val client = PairingClient()
        val pairing = QrPairing(serverUrl = "https://id.example.com/", pairingToken = "t")
        val attested = client.parseRegistration(
            """{"success":true,"deviceId":"d","device":{"userId":"u","canSignOn":true,"attestedLevel":"strongbox","bootState":"locked-verified"}}""", pairing, "Pixel",
        )
        assertEquals("strongbox", attested.attestedLevel); assertEquals("locked-verified", attested.bootState)
        val old = client.parseRegistration("""{"success":true,"deviceId":"d","device":{"userId":"u"}}""", pairing, "Pixel")
        assertEquals("none", old.attestedLevel); assertEquals("unknown", old.bootState)
        val junk = client.parseRegistration("""{"success":true,"deviceId":"d","device":{"userId":"u","attestedLevel":"platinum"}}""", pairing, "Pixel")
        assertEquals("none", junk.attestedLevel)
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `./gradlew testDebugUnitTest --offline --tests 'org.kysecurity.authenticator.pairing.PairingClientTest'`
Expected: FAIL (no `attestationChain` parameter; no `attestedLevel`).

- [ ] **Step 3: Implement**

`PairingStore.kt`:

```kotlin
data class PairedAccount(
    val serverUrl: String,
    val deviceId: String,
    val deviceName: String,
    val username: String? = null,
    val userId: String? = null,
    val canSignOn: Boolean = false,
    /** `none`, `tee` or `strongbox`, as KyIdentity graded the pairing's attestation chain. */
    val attestedLevel: String = "none",
    val bootState: String = "unknown",
)
```

In `account()` read `preferences.getString("attested_level", null) ?: "none"` and `getString("boot_state", null) ?: "unknown"` (named arguments); in `save()` write `attested_level`, `boot_state`; in `clear()` remove both.

`PairingClient.kt`:

```kotlin
    fun register(
        pairing: QrPairing,
        deviceName: String,
        deviceIdentifier: String,
        pushToken: String? = null,
        publicKeyBase64: String = DeviceSigningKey.publicKeyBase64(),
        attestationChain: List<String> = emptyList(),
    ): PairedAccount {
        ...
        val request = registrationRequestJson(pairing, deviceName, deviceIdentifier, pushToken, publicKeyBase64, attestationChain)
```

```kotlin
    internal fun registrationRequestJson(
        pairing: QrPairing,
        deviceName: String,
        deviceIdentifier: String,
        pushToken: String?,
        publicKeyBase64: String,
        attestationChain: List<String> = emptyList(),
    ): String = JSONObject().apply {
        ... existing puts ...
        if (attestationChain.isNotEmpty()) put("attestation", JSONArray(attestationChain))
    }.toString()
```

```kotlin
    private val LEVELS = setOf("none", "tee", "strongbox")

    internal fun parseRegistration(body: String, pairing: QrPairing, deviceName: String): PairedAccount {
        ...
        val level = respDevice?.optString("attestedLevel")?.takeIf { it in LEVELS } ?: "none"
        val boot = respDevice?.optString("bootState")?.takeIf { it.isNotBlank() } ?: "unknown"
        return PairedAccount(..., canSignOn = ..., attestedLevel = level, bootState = boot)
    }
```

Import `org.json.JSONArray`. Update the existing `registrationRequestJson_includes...` test call if its named arguments no longer match.

- [ ] **Step 4: Run tests**

Run: `./gradlew testDebugUnitTest --offline --tests 'org.kysecurity.authenticator.pairing.*'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/org/kysecurity/authenticator/pairing/PairingClient.kt app/src/main/java/org/kysecurity/authenticator/pairing/PairingStore.kt app/src/test/java/org/kysecurity/authenticator/pairing/PairingClientTest.kt
git commit -m "feat(pairing): send the attestation chain and store the attested level"
```

---

### Task 4: Wire pairing and Settings; docs

**Files:**
- Modify: `app/src/main/java/org/kysecurity/authenticator/MainActivity.kt` (pairing thread ~319-328; Settings account section ~2141-2150)
- Modify: `AGENTS.md`

- [ ] **Step 1: Pairing thread**

Replace the `register` call inside the `Thread { runCatching { ... } }` block with:

```kotlin
                            val pushToken = PushTokenProvider.currentToken().getOrThrow()
                            val key = DeviceSigningKey.regenerate(AttestationChallenge.forPairing(pairing))
                            PairingClient().register(
                                pairing = pairing,
                                deviceName = android.os.Build.MODEL,
                                deviceIdentifier = store.deviceIdentifier(),
                                pushToken = pushToken,
                                publicKeyBase64 = key.publicKeyBase64,
                                attestationChain = key.attestationChain,
                            )
```

Import `org.kysecurity.authenticator.pairing.AttestationChallenge`. Confirm both pairing entry points (QR and manual) reach `showPairingConfirmation`, so the manual PIN path also regenerates.

- [ ] **Step 2: Settings**

After the `signOnState` message add:

```kotlin
        val attestation = when (account.attestedLevel) {
            "strongbox" -> "Attested: StrongBox"
            "tee" -> "Attested: TEE"
            else -> "Not attested. Pair again to attest this phone."
        }
        val boot = when (account.bootState) {
            "locked-verified", "locked-selfsigned" -> " Bootloader locked."
            "unlocked" -> " Bootloader unlocked."
            else -> ""
        }
        accountSection.addView(message(attestation + boot))
```

- [ ] **Step 3: AGENTS.md**

Under "Current product contract" replace the sentence "The app generates a hardware-backed P-256 device signing key." with: "Each pairing generates a fresh P-256 device signing key (alias unchanged) with an attestation challenge derived from the pairing credential (`AttestationChallenge`), StrongBox first, TEE fallback, plain key when the device cannot attest. The registration request carries the attestation chain (`attestation`, base64 DER, leaf first); KyIdentity grades it `none`/`tee`/`strongbox` and returns `device.attestedLevel` and `device.bootState`, which `PairedAccount` stores and Settings shows. Re-pairing rotates the key. Only an attested device earns MFA-grade sign-on; see the attestation spec."

Under "Outstanding security work" replace the two KyIdentity-passkey attestation bullets' claims about the device key with: "**Device key attestation positive path unverified.** Emulators ship software KeyMint, so `DeviceSigningKeyAttestationTest` only proves a chain exists; the server grades it `none`. A physical phone paired against a KyIdentity with the attestation verifier is what proves `tee`/`strongbox`. The KyIdentity passkey (`IdentityPasskeyKey`) still has no attestation; the same challenge mechanism could extend to it."

- [ ] **Step 4: Verify and commit**

Run: `./gradlew test lintDebug assembleDebug compileDebugAndroidTestSources --offline`
Expected: PASS.

```bash
git add app/src/main/java/org/kysecurity/authenticator/MainActivity.kt AGENTS.md
git commit -m "feat(pairing): attest the device key at pairing and show the attested level"
```
