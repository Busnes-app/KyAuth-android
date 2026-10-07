# KyAuth Authenticator-Only Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce KyAuth to TOTP, Push MFA, KyIdentity pairing/sign-on and the KyIdentity login passkey, removing KyPasswords sync, the password/passkey vault and Autofill, and fold Push MFA into a renamed Vault tab.

**Architecture:** Almost entirely deletion, landed as three PRs that each build and pass CI on their own. PR 1 cuts the Credential Provider down to the KyIdentity passkey, because today it reads the password vault. PR 2 then deletes every password-vault, KyPasswords and Autofill path, makes `AppLockManager` hold one key, and drops the build/CI machinery that only served them. PR 3 is the UI: a Vault tab with the pending Push MFA request at its top, and a three-part bottom pill.

**Tech Stack:** Kotlin, programmatic Android views (no Compose), Android Keystore, kotpass (KDBX), JUnit 4 unit tests, AndroidX instrumented tests, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-06-vaultwarden-replaces-kypasswords.md`

## Global Constraints

- KyAuth has no Vaultwarden or Bitwarden integration of any kind: no client, sign-in, import, export or link.
- No migration release and no on-device data migration: there is no public build.
- TOTP has no backup, export or sync.
- Frozen identifiers stay: push prefix `kysignon-push-v1`, Keystore alias `kysignon-device-signing-v1`, VaultKek alias `kyauth_vault_kek`, pref key `kek_wrapped_keys`, JSON field `totp`.
- The KyIdentity passkey path never calls `AppLockManager.useVaultKeys` (which is deleted in PR 2) and keeps working while KyAuth is locked.
- Security checks stay fail-closed. Removing a feature must not widen what remains.
- Use `KyAuth` in user-visible text. Rounded, flat buttons; no elevation shadows.
- Each PR ends green on `./gradlew test assembleDebug lintDebug compileDebugAndroidTestSources` and on the CI `verify` and `device` jobs.
- Never run Gradle while the local emulator is running (the machine runs out of memory). Run device tests with Gradle stopped, via `adb shell am instrument`, or let CI run them.

## Review Focus

1. **A native app asks the provider to create a passkey for an unrelated RP ID.** Expect: no create entry, and no Digital Asset Links HTTPS fetch to the caller-named host. Pinned in Task 1.1 by `identityCreateTarget` tests, and the fetch must follow that gate in code order.
2. **A dev install whose wrapped-key blob still holds a `passwords` field.** Expect: TOTP unlocks normally and the extra field is ignored. Pinned in Task 2.3 by `WrappedKeysTest`.
3. **A Push MFA request arrives while there are no TOTP entries.** Expect: the request card shows above the "No codes yet" state. Pinned in Task 3.1 by `VaultTabTest.pendingRequestShowsWithNoTotpEntries`.
4. **A request expires before the Vault tab renders.** Expect: no card, the stored challenge is cleared, and the TOTP list is not centred. Pinned in Task 3.1 by `VaultTabTest.expiredRequestIsClearedAndNotShown`.
5. **Saved state from an older build names a removed tab (`MFA`, `PASSWORDS`, `TOTP`).** Expect: KyAuth opens on Vault. Pinned in Task 3.1 by `TabRestoreTest`.

---

## PR 1: Credential Provider serves only the KyIdentity passkey

Branch: `refactor/provider-identity-only` from `main`.

### Task 1.1: Cut vault paths from the provider service and entry builder

**Files:**
- Modify: `app/src/main/java/org/kysecurity/authenticator/passkeys/KyAuthCredentialProviderService.kt`
- Modify: `app/src/main/java/org/kysecurity/authenticator/passkeys/CredentialEntryBuilder.kt`
- Modify: `app/src/test/java/org/kysecurity/authenticator/passkeys/IdentityPasskeyRoutingTest.kt`
- Delete: `app/src/main/java/org/kysecurity/authenticator/passkeys/CredentialUnlockActivity.kt`
- Modify: `app/src/main/AndroidManifest.xml` (lines 33-37, the `.passkeys.CredentialUnlockActivity` element)

**Interfaces:**
- Produces: `internal fun identityCreateTarget(rpId: String, serverUrl: String?): Boolean` (top level in `CredentialEntryBuilder.kt`).
- Produces: `CredentialEntryBuilder.build(context, request, identityPasskey: IdentityPasskeyRecord?): BeginGetCredentialResponse`.
- Removes: `suppressesVaultPasskeys`, `refusesVaultPasskeyCreate`, `TYPE_PASSWORD`, `TYPE_PASSWORD_ANDX`, `addPasswordEntries`.

- [ ] **Step 1: Write the failing test**

In `IdentityPasskeyRoutingTest.kt`, delete every test from line 53 to the end of the class (the `suppressesVaultPasskeys` and `refusesVaultPasskeyCreate` cases) and add:

```kotlin
    @Test
    fun createIsOfferedOnlyForTheExactPairedHost() {
        assertTrue(identityCreateTarget("id.example.com", "https://id.example.com"))
        assertFalse(identityCreateTarget("example.com", "https://id.example.com"))
        assertFalse(identityCreateTarget("www.id.example.com", "https://id.example.com"))
        assertFalse(identityCreateTarget("evil.test", "https://id.example.com"))
        assertFalse(identityCreateTarget("id.example.com", null))
    }
```

Add `import org.junit.Assert.assertFalse` and `import org.junit.Assert.assertTrue` if missing. Reword the comment at line 40, which mentions `DomainMatcher`, to: `// Exact match only: a leading "www." is a different RP ID.`

- [ ] **Step 2: Run the test to verify it fails**

Run: `./gradlew testDebugUnitTest --tests '*IdentityPasskeyRoutingTest*'`
Expected: compile FAIL, `Unresolved reference: identityCreateTarget`.

- [ ] **Step 3: Rewrite `CredentialEntryBuilder.kt`**

Delete lines 13-14 (the `DomainMatcher` and `PasswordEntry` imports) and lines 16-49 (`suppressesVaultPasskeys`, `refusesVaultPasskeyCreate` and their KDoc). Add in their place:

```kotlin
/**
 * The only RP ID this provider will mint a passkey for: exactly the paired KyIdentity host. Checked
 * before any network work, so an unrelated RP ID costs nothing and reveals nothing.
 */
internal fun identityCreateTarget(rpId: String, serverUrl: String?): Boolean =
    IdentityPasskey.isIdentityRpId(rpId, serverUrl)
```

Replace the object KDoc (lines 51-58) with:

```kotlin
/**
 * Turns a credential query into the entries offered to the user: at most the hardware-backed
 * KyIdentity passkey, which needs no vault key and is offered whether or not KyAuth is unlocked.
 */
```

Replace `build` (lines 62-95) with:

```kotlin
    fun build(
        context: Context,
        request: BeginGetCredentialRequest,
        identityPasskey: IdentityPasskeyRecord?,
    ): BeginGetCredentialResponse {
        val callingAppInfo = request.callingAppInfo
        val origin = callingAppInfo?.origin
        val webOriginHost = ClientData.webOriginHost(origin)
        val callerPackage = callingAppInfo?.packageName
        val callerOrigin = origin ?: ClientData.apkKeyHashOrigin(callingAppInfo?.signingInfo)

        val responseBuilder = BeginGetCredentialResponse.Builder()
        var requestCode = 1000
        for (option in request.beginGetCredentialOptions) {
            if (option.type == TYPE_PUBLIC_KEY || option.type == TYPE_PUBLIC_KEY_ANDX) {
                addPasskeyEntries(
                    context, option, identityPasskey, webOriginHost, callerPackage, callerOrigin,
                    origin, callingAppInfo?.signingInfo, responseBuilder, requestCode++,
                )
            }
        }
        return responseBuilder.build()
    }
```

In `addPasskeyEntries`: delete the `entries: List<PasswordEntry>` and `identityServerUrl: String?` parameters. Replace line 122 and the comment above it (117-122) with:

```kotlin
        // Stop before the DigitalAssetLinks fetch below unless this is the enrolled KyIdentity
        // passkey: that fetch is an HTTPS request to a host the caller names, and it must not reveal
        // whether a KyIdentity passkey is enrolled.
        if (identityPasskey?.rpId != rpId) return
```

Delete the vault block (lines 161-195, `if (!suppressesVaultPasskeys(...)) { ... }`), all of `addPasswordEntries` (198-231), and the `TYPE_PASSWORD`/`TYPE_PASSWORD_ANDX` constants (235-236). Remove the now-unused `Action` import.

- [ ] **Step 4: Rewrite the service**

In `KyAuthCredentialProviderService.kt`, delete imports `java.io.File`, `DomainMatcher`, `KdbxPasswordVault`, `KyAuthAutofillService`, `AppLockManager`, `android.service.credentials.Action`, `android.app.slice.Slice`, `android.app.slice.SliceSpec`, `android.net.Uri`, and `android.app.PendingIntent`. Replace the class KDoc with:

```kotlin
/**
 * System Credential Provider for the KyIdentity login passkey only. It holds no vault and offers
 * no unlock action: the passkey's key is hardware-resident and needs no vault key.
 */
```

Replace `buildGetResponse` and delete `unlockAction()`:

```kotlin
    private fun buildGetResponse(request: BeginGetCredentialRequest): BeginGetCredentialResponse {
        // EncryptedSharedPreferences can throw after a device restore or keyset invalidation; fail
        // closed rather than crash the process.
        val identityPasskey = runCatching { IdentityPasskeyStore(this).record() }.getOrNull()
            ?: return BeginGetCredentialResponse.Builder().build()
        return CredentialEntryBuilder.build(this, request, identityPasskey)
    }
```

In `buildCreateResponse`, replace lines 132-175 (DAL check, pairing read, `isIdentity`, `refusesVaultPasskeyCreate`, the title/subtitle `if`s and the action `if`) so that the pairing gate runs before the DAL fetch:

```kotlin
                // A failed pairing read cannot rule out KyIdentity, so it refuses.
                val pairing = runCatching { PairingStore(this).account()?.serverUrl }
                if (pairing.isFailure) return responseBuilder.build()
                // Only the exact paired KyIdentity host, and before any network work.
                if (!identityCreateTarget(rpId, pairing.getOrNull())) return responseBuilder.build()
                if (webOriginHost == null &&
                    !DigitalAssetLinks.isCallerAuthorized(rpId, callerPackage, callingAppInfo?.signingInfo)
                ) {
                    return responseBuilder.build()
                }
                val userObj = json.optJSONObject("user")
                val username = userObj?.optString("name")?.ifBlank { null }
                    ?: userObj?.optString("displayName").orEmpty()
                val title = "Create KyIdentity Passkey"
                val subtitle = "Stays on this device, in secure hardware"

                val intent = Intent(this, CredentialAuthActivity::class.java).apply {
                    putExtra(CredentialAuthActivity.EXTRA_ACTION, CredentialAuthActivity.ACTION_CREATE_IDENTITY_PASSKEY)
```

Keep the remaining `putExtra` lines and `setCreateEntries` block (old 176-204) unchanged. Change `when (request.type) { CredentialEntryBuilder.TYPE_PUBLIC_KEY, ... -> { ... } TYPE_PASSWORD ... }` into a guard: delete the whole password branch (old 206-238), and keep the passkey body under `if (request.type == CredentialEntryBuilder.TYPE_PUBLIC_KEY || request.type == CredentialEntryBuilder.TYPE_PUBLIC_KEY_ANDX) { ... }`.

- [ ] **Step 5: Delete the unlock activity**

```bash
git rm app/src/main/java/org/kysecurity/authenticator/passkeys/CredentialUnlockActivity.kt
```

Delete its `<activity android:name=".passkeys.CredentialUnlockActivity" ... />` element from `AndroidManifest.xml`.

- [ ] **Step 6: Fix the two other users of the deleted predicates**

`CredentialAuthActivity.kt` uses `suppressesVaultPasskeys` in `handleCreatePasskey`; Task 1.2 deletes that function. `MainActivity.kt` uses it for the "stranded passkey" badge in `renderPasswordsTab`. Replace that block:

```kotlin
            val stranded = entry.passkey?.let {
                suppressesVaultPasskeys(it.rpId, pairedServerUrl)
            } == true
```

with `val stranded = false`, delete the comment above it, and delete the `import org.kysecurity.authenticator.passkeys.suppressesVaultPasskeys` line. PR 2 deletes the whole tab; this keeps PR 1 compiling. The routing test runs at the end of Task 1.2.

### Task 1.2: Cut vault actions from `CredentialAuthActivity` and vault-only engine helpers

**Files:**
- Modify: `app/src/main/java/org/kysecurity/authenticator/passkeys/CredentialAuthActivity.kt`
- Modify: `app/src/main/java/org/kysecurity/authenticator/passkeys/WebAuthnEngine.kt`
- Modify: `app/src/test/java/org/kysecurity/authenticator/passkeys/WebAuthnEngineTest.kt`
- Modify: `app/src/test/java/org/kysecurity/authenticator/passkeys/WebAuthnAssertionTest.kt`
- Modify: `app/src/main/res/values/strings.xml` (`generate_strong_password`)

**Interfaces:**
- Consumes: `CredentialEntryBuilder.build(context, request, identityPasskey)` from Task 1.1.
- Removes: `CredentialAuthActivity.ACTION_GET_PASSKEY`, `ACTION_GET_PASSWORD`, `ACTION_CREATE_PASSKEY`, `ACTION_CREATE_PASSWORD`, `EXTRA_ENTRY_ID`, `EXTRA_PASSWORD`, `EXTRA_DOMAIN`, `TYPE_PASSWORD_CREDENTIAL`; `WebAuthnEngine.generateEcKeyPair`, `restorePrivateKey`, `signAssertion(ECPrivateKey, …)`.

- [ ] **Step 1: Point the tests at plain JCA keys (they fail to compile once the helpers go)**

In both test files, add the helper to the class:

```kotlin
    private fun p256(): java.security.KeyPair = java.security.KeyPairGenerator.getInstance("EC")
        .apply { initialize(java.security.spec.ECGenParameterSpec("secp256r1")) }
        .generateKeyPair()

    private fun signWith(keyPair: java.security.KeyPair, authData: ByteArray, hash: ByteArray) =
        WebAuthnEngine.signAssertion(
            java.security.Signature.getInstance("SHA256withECDSA").apply { initSign(keyPair.private) },
            authData,
            hash,
        )
```

Replace every `WebAuthnEngine.generateEcKeyPair()` with `p256()`. Replace each `WebAuthnEngine.signAssertion(WebAuthnEngine.restorePrivateKey(keyPair.private.encoded), a, b)` and `WebAuthnEngine.signAssertion(privateKey, a, b)` with `signWith(keyPair, a, b)`. In `WebAuthnEngineTest.generatesValidEcKeyPairAndSignsAssertion`, delete line 17 (`val privateKey = ...`). Delete the test `` `signing through a Signature matches signing through a private key` `` (WebAuthnAssertionTest 101-119): with one overload left it compares nothing.

- [ ] **Step 2: Delete the vault-only engine helpers**

In `WebAuthnEngine.kt`, delete `generateEcKeyPair()`, `restorePrivateKey()`, and the `signAssertion(privateKey: ECPrivateKey, …)` overload, plus imports that become unused (`KeyFactory`, `KeyPair`, `KeyPairGenerator`, `ECGenParameterSpec`, `PKCS8EncodedKeySpec`, `ECPrivateKey`). Keep `generateCredentialId` and its `SecureRandom` import.

- [ ] **Step 3: Cut the activity**

In `CredentialAuthActivity.kt`:
- Delete imports `android.text.InputType`, `java.io.File`, `java.security.interfaces.ECPublicKey`, `java.util.UUID`, `javax.crypto.Cipher`, `android.widget.Toast` (if unused afterwards), and every `org.kysecurity.authenticator.passwords.*` import plus `security.AppLockManager`. Keep `security.VaultUnlockPrompt`.
- Delete `private lateinit var passwordInput: EditText`.
- Replace `isCreation` (77-79) with `val isCreation = action == ACTION_CREATE_IDENTITY_PASSKEY`.
- Delete the `if (action == ACTION_CREATE_PASSWORD) { ... }` block (132-170) and change the following `else if (action == ACTION_CREATE_PASSKEY || action == ACTION_CREATE_IDENTITY_PASSKEY)` to `if (action == ACTION_CREATE_IDENTITY_PASSKEY)`.
- Replace `authenticateAndExecute` with:

```kotlin
    private fun authenticateAndExecute(action: String) {
        when (action) {
            ACTION_GET_IDENTITY_PASSKEY -> getIdentityPasskey()
            ACTION_CREATE_IDENTITY_PASSKEY -> createIdentityPasskey()
            else -> finishWithFailure("Unknown credential action: $action")
        }
    }
```

- In the `getIdentityPasskey` KDoc, replace "Deliberately never calls [AppLockManager.useVaultKeys]: the private key is non-exportable and there is no vault key to unwrap, so this path is unaffected by the password vault's state." with "The private key is non-exportable and needs no vault key, so this works while KyAuth is locked." Replace "Known and deliberate, as on the vault path:" with "Known and deliberate:".
- Delete `executeCredentialAction`, `handleGetPasskey`, `handleGetPassword`, `handleCreatePasskey`, `handleCreatePassword` and `failed` (517-780).
- Delete the companion constants `ACTION_GET_PASSKEY`, `ACTION_GET_PASSWORD`, `ACTION_CREATE_PASSKEY`, `ACTION_CREATE_PASSWORD`, `EXTRA_ENTRY_ID`, `EXTRA_PASSWORD`, `EXTRA_DOMAIN`, `TYPE_PASSWORD_CREDENTIAL`.

Delete `<string name="generate_strong_password">` from `strings.xml`.

- [ ] **Step 4: Run the full check**

Run: `./gradlew test assembleDebug lintDebug compileDebugAndroidTestSources`
Expected: PASS, including `IdentityPasskeyRoutingTest.createIsOfferedOnlyForTheExactPairedHost`. `grep -rn "useVaultKeys\|getPasswordVaultKey\|KdbxPasswordVault\|DomainMatcher" app/src/main/java/org/kysecurity/authenticator/passkeys` prints nothing.

- [ ] **Step 5: Update `AGENTS.md`**

Replace the bullet starting "KyAuth acts as an Android 14+ (API 34+) system Credential Provider for both Passkeys and Passwords" with:

```markdown
- KyAuth is an Android 14+ (API 34+) system Credential Provider for one credential: the KyIdentity
  login passkey (`KyAuthCredentialProviderService`, `CredentialAuthActivity`). It mints a passkey only
  for the exact paired KyIdentity host (`identityCreateTarget`), checked before any network work.
```

Delete the bullet starting "While locked, neither provider touches vault material" and the "Credential picker accumulation is unverified" item under Outstanding security work. In the "A passkey whose RP ID is the paired KyIdentity server's host" bullet, delete the sentence "The Credential Provider therefore offers this one entry while KyAuth is locked, alongside the unlock action." and replace it with "The Credential Provider offers it whether or not KyAuth is unlocked."

- [ ] **Step 6: Commit and open PR 1**

```bash
git add -A app/src AGENTS.md
git commit -m "refactor(passkeys): the provider serves only the KyIdentity passkey"
git push -u origin refactor/provider-identity-only
gh pr create --fill
```

---

## PR 2: Remove KyPasswords, the password vault and Autofill

Branch: `refactor/remove-password-vault` from `main` after PR 1 merges.

### Task 2.1: Delete the passwords package, keeping `PublicSuffix`

**Files:**
- Move: `app/src/main/java/org/kysecurity/authenticator/passwords/PublicSuffix.kt` → `app/src/main/java/org/kysecurity/authenticator/passkeys/PublicSuffix.kt`
- Modify: `app/src/main/java/org/kysecurity/authenticator/passkeys/RpId.kt:3`
- Modify: `app/src/test/java/org/kysecurity/authenticator/passkeys/RpIdTest.kt`
- Delete: the rest of `app/src/main/java/org/kysecurity/authenticator/passwords/` (including `kypasswords/`)
- Delete: `app/src/test/java/org/kysecurity/authenticator/passwords/`, `app/src/androidTest/java/org/kysecurity/authenticator/passwords/`, `app/src/test/resources/{kypasswords-web-vault,vault-preservation,vault-recycling-disabled}.kdbx`
- Delete: `app/src/main/java/org/kysecurity/authenticator/passkeys/PasskeyQr.kt`, `app/src/test/java/org/kysecurity/authenticator/passkeys/PasskeyQrTest.kt`
- Delete: `app/src/main/res/xml/autofill_service.xml`; manifest elements `.passwords.AutofillUnlockActivity` and `.passwords.KyAuthAutofillService`

**Interfaces:**
- Produces: `org.kysecurity.authenticator.passkeys.PublicSuffix.isPublicSuffix(host: String): Boolean` (same body, new package).

- [ ] **Step 1: Move PublicSuffix and its only direct asserts**

```bash
git mv app/src/main/java/org/kysecurity/authenticator/passwords/PublicSuffix.kt app/src/main/java/org/kysecurity/authenticator/passkeys/PublicSuffix.kt
sed -i 's/^package org.kysecurity.authenticator.passwords$/package org.kysecurity.authenticator.passkeys/' app/src/main/java/org/kysecurity/authenticator/passkeys/PublicSuffix.kt
sed -i '/^import org.kysecurity.authenticator.passwords.PublicSuffix$/d' app/src/main/java/org/kysecurity/authenticator/passkeys/RpId.kt
```

Add to `RpIdTest.kt` (these replace the `PublicSuffix` asserts in the soon-deleted `DomainMatcherTest`):

```kotlin
    @Test
    fun publicSuffixListCoversWildcardAndExceptionRules() {
        assertTrue(PublicSuffix.isPublicSuffix("foo.ck"))
        assertFalse(PublicSuffix.isPublicSuffix("www.ck"))
        assertTrue(PublicSuffix.isPublicSuffix("co.uk"))
        assertFalse(PublicSuffix.isPublicSuffix("example.co.uk"))
    }
```

- [ ] **Step 2: Run it**

Run: `./gradlew testDebugUnitTest --tests '*RpIdTest*'`
Expected: PASS.

- [ ] **Step 3: Delete the rest**

```bash
git rm -r app/src/main/java/org/kysecurity/authenticator/passwords \
  app/src/test/java/org/kysecurity/authenticator/passwords \
  app/src/androidTest/java/org/kysecurity/authenticator/passwords \
  app/src/test/resources/kypasswords-web-vault.kdbx \
  app/src/test/resources/vault-preservation.kdbx \
  app/src/test/resources/vault-recycling-disabled.kdbx \
  app/src/main/java/org/kysecurity/authenticator/passkeys/PasskeyQr.kt \
  app/src/test/java/org/kysecurity/authenticator/passkeys/PasskeyQrTest.kt \
  app/src/main/res/xml/autofill_service.xml
```

Delete the `.passwords.AutofillUnlockActivity` and `.passwords.KyAuthAutofillService` elements from `AndroidManifest.xml`. In `totp/KdbxTotpVault.kt:21`, replace the KDoc `/** Serialized like [org.kysecurity.authenticator.passwords.KdbxPasswordVault]; load throws on a corrupt vault. */` with `/** Load throws on a corrupt vault. */`.

The build is red until Tasks 2.2 and 2.3; do not commit yet.

### Task 2.2: Strip the password features from `MainActivity`

**Files:**
- Modify: `app/src/main/java/org/kysecurity/authenticator/MainActivity.kt`
- Modify: `app/src/main/java/org/kysecurity/authenticator/security/SecurityWipe.kt`
- Modify: `app/src/main/res/values/strings.xml`

Line numbers are from `main` at `c241fc3`; after PR 1 they may shift by a few lines. Locate by function name.

- [ ] **Step 1: Delete whole functions**

Delete: `readPasswordVault`, `showPasskeyQrDialog`, `scanPasskeyQr`, `loadPasswordEntries`, `mutatePasswords`, the "Tab 3: Password Vault" section comment, `renderPasswordsTab`, `showRecycleBin`, `showReusedPasswords`, `createLocalPasswordVault`, `showAddPasswordDialog`, `showPasswordDetails`, `generatePassword`, the "KyPasswords Server Pairing & Sync Helpers" section comment, `showPairKyPasswordsDialog`, `scanKyPasswordsQr`, `showManualKyPasswordsPairingDialog`, `redeemAndUnlockKyPasswords`, `showUploadLocalVaultDialog`, `showUnlockKyPasswordsDialog`, `unlockKyPasswords`, `syncKyPasswordsVault`, `showResolveVaultConflict`, `confirmVaultResolution`, `showSyncErrorDialog`, `confirmUnpairKyPasswords`, `confirmRevealOfflineVaultKey` (with its KDoc), `showOfflineVaultKey`. Keep `addTotpEntry` and `queueTotpEntry`, which sit between `mutatePasswords` and the Passwords section.

- [ ] **Step 2: Delete fields**

Delete `pendingConflictExport`, the `exportConflicts` launcher, `kyPasswordStore`, `kyPasswordClient`, `vaultReportDialog`, `vaultReportRequest`, `refreshVaultReport`, `passwordEntries`, `passwordVaultFile`. Keep `isVaultLoading`, `vaultLoadGeneration`, `executor`, `pendingChallenge`.

- [ ] **Step 3: Edit the survivors**

- `onCreate`: delete `Thread { KyPasswordVaultSync.clearInterruptedSnapshots(filesDir) }.start()`.
- `onResume`: delete `runCatching { loadPasswordEntries() }`.
- `onDestroy` and `lockSensitiveState`: delete `passwordEntries.clear()`.
- `renderActiveTab`: delete the `Tab.PASSWORDS -> renderPasswordsTab(container)` arm, and remove `PASSWORDS` from `enum class Tab`.
- `bottomNavigation`: delete `addView(destination(getString(R.string.tab_passwords), Tab.PASSWORDS))`.
- `showKyDialog`: delete the `if (vaultReportDialog === this) { ... }` lines.
- `unlockVault`: load only TOTP. Replace the `passwords` load and the pair with the TOTP list alone, so the success handler reads `result.onSuccess { totp -> ... }` and no longer assigns `passwordEntries`.
- `renderSettingsTab`: delete `kyPasswordsSection` and `offlineKeySection`. Replace the `providerSection` text with title "KyIdentity passkey provider" and message "Enable KyAuth as a passkey provider so KyIdentity sign-in can use this phone's passkey." Keep its button calling `openCredentialProviderSettings()`.
- `openCredentialProviderSettings`: delete the Autofill intent (`Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE` with its `Uri`) and its `runCatching`; keep the `"android.settings.CREDENTIAL_PROVIDER"` intent and the `Settings.ACTION_SETTINGS` fallback.

- [ ] **Step 4: Delete unused imports**

Delete: `android.content.ActivityNotFoundException`, `android.net.Uri`, `pairing.PairingEndpoint`, `passkeys.PasskeyQr`, `passkeys.suppressesVaultPasskeys` (if PR 1 left it), every `passwords.*` and `passwords.kypasswords.*` import, `security.CredentialCipher`, `security.SecurityWipe`, `totp.TotpGenerator`, `java.security.SecureRandom`. Lint flags any import still unused.

- [ ] **Step 5: SecurityWipe and strings**

In `SecurityWipe.kt`, delete the `KyPasswordStore` import and `runCatching { KyPasswordStore(context).clear() }`, and change the comment to `// 1. Wipe PairingStore and the KyIdentity passkey record`.

Delete these strings from `strings.xml`: `sync_issue`, `sync_issue_action`, `passkey_badge`, `identity_passkey_restranded`, `local_password_storage`, `webauthn_passkey`, `passkey_details`, `pair_kypasswords_server`, `pair_kypasswords_description`, `manual_kypasswords_pairing`, `unlock_kypasswords_keyfile`, `unlock_kypasswords_description`, `tab_passwords`.

### Task 2.3: One key in `AppLockManager`

**Files:**
- Modify: `app/src/main/java/org/kysecurity/authenticator/security/AppLockManager.kt`
- Create: `app/src/test/java/org/kysecurity/authenticator/security/WrappedKeysTest.kt`

**Interfaces:**
- Produces: `internal fun parseWrappedKeys(plain: ByteArray): ByteArray` and `internal fun serializeWrappedKeys(totpKey: ByteArray): ByteArray` (top level in `AppLockManager.kt`).
- Removes: `VaultKeys`, `getPasswordVaultKey`, `hasPasswordVaultKey`, `setPasswordVaultKey`, `clearPasswordVaultKey`, `useVaultKeys`.

- [ ] **Step 1: Write the failing test**

```kotlin
package org.kysecurity.authenticator.security

import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Test

class WrappedKeysTest {
    private val totp = ByteArray(32) { it.toByte() }
    private fun b64(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)

    @Test
    fun roundTrips() {
        assertArrayEquals(totp, parseWrappedKeys(serializeWrappedKeys(totp)))
    }

    @Test
    fun ignoresThePasswordsKeyOlderDevBuildsWrote() {
        val old = """{"totp":"${b64(totp)}","passwords":"${b64(ByteArray(32) { 7 })}"}"""
        assertArrayEquals(totp, parseWrappedKeys(old.toByteArray()))
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `./gradlew testDebugUnitTest --tests '*WrappedKeysTest*'`
Expected: compile FAIL, `Unresolved reference: parseWrappedKeys`.

- [ ] **Step 3: Implement**

Add at the top level of `AppLockManager.kt`:

```kotlin
/** The VaultKek-wrapped plaintext: `{"totp": base64}`. Unknown fields from older builds are ignored. */
internal fun serializeWrappedKeys(totpKey: ByteArray): ByteArray =
    JSONObject().put("totp", Base64.getEncoder().encodeToString(totpKey)).toString().toByteArray(Charsets.UTF_8)

internal fun parseWrappedKeys(plain: ByteArray): ByteArray =
    Base64.getDecoder().decode(JSONObject(String(plain, Charsets.UTF_8)).getString("totp"))
```

Then in `AppLockManager`:
- Class KDoc: "Owns the lock state and the TOTP vault key, wrapped by [VaultKek], an authentication-bound Keystore key: unwrapping requires a cipher the framework has already authenticated."
- Delete constants `KEY_HAS_PASSWORD_VAULT_KEY`, `KEY_PASSWORD_VAULT_SALT`, `KEY_WRAPPED_PASSWORD_VAULT_KEY`, `LEGACY_BIOMETRIC_WRAPPED_PASSWORD_VAULT_KEY`, `JSON_TOTP`, `JSON_PASSWORDS`.
- Delete `VaultKeys`, `activePasswordVaultKey` and its two lines in `lock()`, `getPasswordVaultKey`, `hasPasswordVaultKey`, `setPasswordVaultKey`, `clearPasswordVaultKey`, `useVaultKeys`, `unlockPasswordVaultWithPin`, and the password block in `setupPin` (old 164-171).
- `unlockWithBiometrics`: the `else` arm becomes `else -> CredentialCipher.generateVaultKey()`; the value is a `ByteArray` named `key`, passed to `adopt(context, key)`.
- `unlockWithPin`: `adopt(context, vaultKey)`.
- `adopt(context, key: ByteArray)`: `activeVaultKey?.fill(0); activeVaultKey = key; isUnlocked = true; persistWrappedKeys(context)`.
- `unwrapKeys(context, cipher): ByteArray?`: unwrap, then `parseWrappedKeys(plain).also { plain.fill(0) }`.
- `persistWrappedKeys`: `val wrapped = VaultKek.wrap(serializeWrappedKeys(totpKey))`; drop `.putBoolean(KEY_HAS_PASSWORD_VAULT_KEY, …)` and the password legacy `.remove`.
- `migrateLegacyWrapping(context): ByteArray?`: return the TOTP key only.

In `VaultKek.kt:15` and `:43` and `VaultUnlockPrompt.kt:11`, say "the vault key" instead of "the vault keys"; in `VaultUnlockPrompt.kt:62`, drop "while the password vault is locked or compromised".

- [ ] **Step 4: Run the tests**

Run: `./gradlew testDebugUnitTest --tests '*WrappedKeysTest*'`
Expected: PASS.

### Task 2.4: Build, CI, tools and docs

**Files:**
- Modify: `app/build.gradle.kts` (BouncyCastle excludes lines 90-91; okio lines 105-106; BouncyCastle lines 107-110)
- Modify: `.github/workflows/android.yml` (lines 17-21, 23)
- Delete: `tools/vault_preservation.js`, `tools/gen_kdbx_interop_fixture.js`, `tools/gen_argon2id_envelope_fixture.py`, `tools/package.json`, `tools/package-lock.json`
- Delete: `docs/plans/2026-09-05-vault-parity.md`, `docs/plans/2026-09-05-vault-parity-verification.md`, `docs/passkey-qr-handoff.md`
- Modify: `CONTRIBUTING.md:27-28`, `STYLE_GUIDE.md:40`, `prompt.md:9,20-24`, `AGENTS.md`

- [ ] **Step 1: Build file**

Delete the two `excludes += "/org/bouncycastle/…"` lines, the okio `compileOnly` line and its comment, and the BouncyCastle `implementation` line and its comment. Keep Guava (`PublicSuffix`) and `testImplementation("org.json:json:…")`.

- [ ] **Step 2: Run the full check**

Run: `./gradlew test assembleDebug lintDebug compileDebugAndroidTestSources`
Expected: PASS. If okio's removal breaks kotpass compilation in `totp/`, restore that one line and its comment, reworded to name `KdbxTotpVault`.

- [ ] **Step 3: CI and tools**

In `.github/workflows/android.yml`, delete the `actions/setup-node` step, `npm ci --prefix tools --ignore-scripts`, `pip install argon2-cffi==25.1.0` and `node tools/vault_preservation.js app/build/interop`. Keep `tools/unlock_test_emulator.py`.

```bash
git rm tools/vault_preservation.js tools/gen_kdbx_interop_fixture.js tools/gen_argon2id_envelope_fixture.py tools/package.json tools/package-lock.json \
  docs/plans/2026-09-05-vault-parity.md docs/plans/2026-09-05-vault-parity-verification.md docs/passkey-qr-handoff.md
```

- [ ] **Step 4: Docs**

- `CONTRIBUTING.md`: replace lines 27-28 with `- KyAuth stores no passwords and no non-KyIdentity passkeys; those belong to the Bitwarden app.`
- `STYLE_GUIDE.md`: delete line 40.
- `prompt.md`: delete line 9 and lines 20-24.
- `AGENTS.md`:
  - Delete the bullets that start "The KyPasswords key envelope", "KDBX entry fields use the KeePass wire names", "Passwords and Passkeys use `passwords_vault.kdbx`", "Autofill believes a request's `webDomain`", "Password fill matches an entry's domain", "Incremental password/passkey edits", "`KyPasswordVaultSync` serializes sync sessions", "The Passwords tab supports pairing with KyPasswords", "The Passwords Recycle Bin", "Reused passwords compares", "Copied passwords are marked sensitive".
  - Replace "Both vault keys are wrapped by `VaultKek`" and "One authentication yields one unwrap, so both keys share a single wrapped blob." with: "The TOTP vault key is wrapped by `VaultKek`, an authentication-bound Keystore RSA-OAEP key (`setUserAuthenticationRequired(true)`, per-use), as `{"totp": base64}`. Wrapping needs no prompt; unwrapping requires a `BiometricPrompt.CryptoObject`. A device without a secure lock screen cannot use KyAuth."
  - UI contract: delete the passkey QR bullet; change the pill bullet to "Use the four-part bottom pill: TOTP Vault, Push MFA, lock shield, Settings." (PR 3 changes it again).
  - Project layout: delete the `passwords/` line; in `passkeys/` drop "unlock activity" and add "`PublicSuffix`".
  - Verification: the block becomes only `./gradlew test lintDebug assembleDebug compileDebugAndroidTestSources`; delete the `KdbxPreservationTest` paragraph.
  - Outstanding security work: delete "Non-Play browser builds", "Vault size ceilings", "Non-KyIdentity passkey private keys are exportable". In "Device verification", delete "`useVaultKeys`, provider unlock flows,". In "Deprecated platform APIs", delete the `Dataset`/`FillResponse` builders.
  - Work guidance: delete the "KyAuth is becoming authenticator-only" bullet (it is done).

- [ ] **Step 5: Prove nothing references the removed code**

```bash
grep -rIn -i "kypassword\|passwords_vault\|KdbxPasswordVault\|useVaultKeys\|getPasswordVaultKey\|bouncycastle\|vault_preservation\|AutofillService" app/src .github tools AGENTS.md CONTRIBUTING.md STYLE_GUIDE.md prompt.md
```

Expected: no output.

Run: `./gradlew test assembleDebug lintDebug compileDebugAndroidTestSources`
Expected: PASS.

- [ ] **Step 6: Commit and open PR 2**

```bash
git add -A
git commit -m "refactor: remove KyPasswords, the password vault and Autofill"
git push -u origin refactor/remove-password-vault
gh pr create --fill
```

---

## PR 3: Vault tab with Push MFA at its top

Branch: `feat/vault-tab` from `main` after PR 2 merges.

### Task 3.1: Rename the tab, move the request card, drop the Push MFA tab

**Files:**
- Modify: `app/src/main/java/org/kysecurity/authenticator/MainActivity.kt`
- Modify: `app/src/main/res/values/strings.xml`
- Create: `app/src/test/java/org/kysecurity/authenticator/TabRestoreTest.kt`
- Create: `app/src/androidTest/java/org/kysecurity/authenticator/VaultTabTest.kt`
- Modify: `AGENTS.md`, `STYLE_GUIDE.md`

**Interfaces:**
- Produces: `enum class Tab { VAULT, SETTINGS }` with `companion object { fun restore(name: String?): Tab }` inside `MainActivity`.
- Produces: `private fun renderPendingChallenge(container: LinearLayout, account: PairedAccount)`.

- [ ] **Step 1: Write the failing unit test**

```kotlin
package org.kysecurity.authenticator

import org.junit.Assert.assertEquals
import org.junit.Test

class TabRestoreTest {
    @Test
    fun removedOrMissingTabsOpenVault() {
        for (old in listOf(null, "", "TOTP", "MFA", "PASSWORDS", "nonsense")) {
            assertEquals("restore($old)", MainActivity.Tab.VAULT, MainActivity.Tab.restore(old))
        }
        assertEquals(MainActivity.Tab.SETTINGS, MainActivity.Tab.restore("SETTINGS"))
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `./gradlew testDebugUnitTest --tests '*TabRestoreTest*'`
Expected: compile FAIL, `Unresolved reference: VAULT`.

- [ ] **Step 3: Implement the tab change**

```kotlin
    enum class Tab {
        VAULT, SETTINGS;

        companion object {
            fun restore(name: String?): Tab = entries.firstOrNull { it.name == name } ?: VAULT
        }
    }
```

- `activeTab` defaults to `Tab.VAULT`. In `onCreate`, `activeTab = Tab.restore(savedInstanceState?.getString(STATE_ACTIVE_TAB))`.
- Rename every remaining `Tab.TOTP` to `Tab.VAULT` (the ticker check, `bottomNavigation`).
- `loadPendingPushChallenge`: `activeTab = Tab.VAULT`.
- `renderActiveTab`: `Tab.VAULT -> renderTotpTab(container, account)` and `Tab.SETTINGS -> renderSettingsTab(container, account)`; delete the `Tab.MFA` arm.
- `bottomNavigation`: delete `addView(destination(getString(R.string.tab_approvals), Tab.MFA))`.
- `strings.xml`: `<string name="tab_totp">Vault</string>`; delete `tab_approvals`, `no_pending_challenges`, `mfa_empty_description`.

- [ ] **Step 4: Move the card**

Rename `renderMfaTab` to `renderPendingChallenge` and change its start so it adds nothing when there is no live request and never centres the container:

```kotlin
    /** The pending Push MFA request, at the top of Vault. Adds nothing when none is live. */
    private fun renderPendingChallenge(container: LinearLayout, account: PairedAccount) {
        val challenge = pendingChallenge ?: return
        val challengeStore = MfaPushChallengeStore(this)
        if (challengeStore.isExpired(challenge)) {
            pendingChallenge = null
            challengeStore.clear()
            return
        }
```

Keep the card body unchanged, but add it with `container.addView(card, fullWidthParams(bottom = 16))` and give the two buttons `fullWidthParams(bottom = 8)`. Delete `mfaEmptyState()` and the "Tab 4: Push MFA Approvals" section comment.

Change `renderTotpTab(container: LinearLayout)` to `renderTotpTab(container: LinearLayout, account: PairedAccount)` and call `renderPendingChallenge(container, account)` immediately after `container.addView(headerRow)` and before the `if (totpEntries.isEmpty())` early return.

- [ ] **Step 5: Run the unit test**

Run: `./gradlew testDebugUnitTest --tests '*TabRestoreTest*'`
Expected: PASS.

- [ ] **Step 6: Write the device test**

```kotlin
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

    private fun challenge(expiresInMs: Long) = MfaChallenge(
        challengeId = "c1", matchDigits = "42", decoyDigits = listOf("17"),
        serverUrl = "https://example.test", username = "fixture-user",
        expiresAtEpochMs = System.currentTimeMillis() + expiresInMs,
    )

    @Test fun pendingRequestShowsWithNoTotpEntries() {
        MfaPushChallengeStore(context).save(challenge(60_000))
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val shown = texts(activity.window.decorView)
                assertTrue(shown.contains("Sign-in Request"))
                assertTrue(shown.contains("No codes yet"))
                assertTrue(shown.indexOf("Sign-in Request") < shown.indexOf("No codes yet"))
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
                assertFalse(texts(activity.window.decorView).contains("Sign-in Request"))
            }
        }
        assertNull(MfaPushChallengeStore(context).load())
    }
}
```

- [ ] **Step 7: Run the full check, then the device test with Gradle stopped**

Run: `./gradlew test assembleDebug lintDebug compileDebugAndroidTestSources installDebug installDebugAndroidTest && ./gradlew --stop`
Expected: PASS.

Then start the emulator, unlock it, and run:
`adb shell am instrument -w -e class org.kysecurity.authenticator.VaultTabTest org.kysecurity.authenticator.test/androidx.test.runner.AndroidJUnitRunner`
Expected: `OK (2 tests)`. Shut the emulator down afterwards (`adb emu kill`).

- [ ] **Step 8: Docs**

- `AGENTS.md`:
  - Pill bullet becomes "Use the three-part bottom pill: Vault, lock shield, Settings."
  - "The TOTP Vault screen provides a + icon" becomes "The Vault screen shows a pending Push MFA request at its top, then the TOTP list with a + icon to scan QR or add accounts manually with optional Website and Notes fields."
  - In the Push MFA bullet, "opens the Push MFA tab for approve/deny" becomes "opens Vault, where the request card at the top approves or denies it".
- `STYLE_GUIDE.md`: delete "Use a centered card for an empty Push MFA screen."
- Spec `docs/superpowers/specs/2026-10-06-vaultwarden-replaces-kypasswords.md`: change "Status: decided, not implemented." to "Status: implemented."

- [ ] **Step 9: Commit and open PR 3**

```bash
git add -A
git commit -m "feat(ui): Vault tab with the pending Push MFA request at its top"
git push -u origin feat/vault-tab
gh pr create --fill
```
