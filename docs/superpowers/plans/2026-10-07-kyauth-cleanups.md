# KyAuth Cleanups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Drop the deprecated `EncryptedSharedPreferences`, stop hand-building credential-provider `Slice`s, and split `MainActivity` into focused files — with no behavior change for users.

**Architecture:** Three independent PRs, landed in this order, each from `main` after the previous merges (no stacked PRs): A plain prefs, B androidx-built provider entries, C the split (last, because it touches everything).

**Tech Stack:** Kotlin, Android views, `androidx.credentials` (B only), JUnit 4, AndroidX instrumented tests.

**Spec:** none; these are refactors. Behavior contracts are the current `AGENTS.md`. Provider findings come from the 2026-10-07 code survey recorded here.

## Global Constraints

- No user-visible behavior change except what a task names.
- No public build exists; dev installs may need to re-pair after A (accepted, no migration).
- Security checks stay fail-closed: the provider's pairing gate and `identityCreateTarget` run before any Digital Asset Links fetch; the get path's enrolled-RP check precedes it; the privileged `clientDataHash` rule is unchanged.
- Do not run Gradle while an emulator runs. Verify with `./gradlew test assembleDebug lintDebug compileDebugAndroidTestSources`.
- Each PR updates `AGENTS.md` where it describes the changed code.

## Review Focus

1. **Local wipe after A.** Expect: pairing, identity-passkey record, push challenge and push token prefs all gone, old encrypted files and the androidx master key deleted. Pinned in Task A.
2. **A corrupt/unreadable store after A.** Expect: treated as unpaired / no passkey, no crash. Pinned in Task A (plain prefs cannot fail decryption; construction is no longer wrapped).
3. **Provider entries after B.** Expect: same title/subtitle/intent and request codes as before. Pinned in Task B by unit tests on the entry inputs where the builder allows, plus device check noted as unverified.
4. **Reflection tests after C.** Expect: `VaultTabTest`, `LockClearsDialogsTest` call the moved members directly (now `internal`), not by reflection names. Pinned in Task C.
5. **Push approve/deny after C.** Expect: one shared respond path, same results. Pinned by existing `VaultTabTest` plus Task C's unit-level check.

---

### Task A: Plain prefs replace EncryptedSharedPreferences

Branch `refactor/plain-prefs` from `main`.

**Files:**
- Modify: `app/src/main/java/org/kysecurity/authenticator/pairing/PairingStore.kt`, `app/src/main/java/org/kysecurity/authenticator/passkeys/IdentityPasskeyStore.kt`
- Modify: `app/src/main/java/org/kysecurity/authenticator/security/SecurityWipe.kt`
- Modify: `app/src/test/java/org/kysecurity/authenticator/security/SecurityWipeAliasTest.kt`
- Modify: `app/build.gradle.kts` (remove `androidx.security:security-crypto`)
- Modify: `AGENTS.md` ("encrypted pairing store" wording; Deprecated platform APIs item)
- Test: `app/src/androidTest/java/org/kysecurity/authenticator/passkeys/IdentityPasskeyStoreTest.kt`

Neither store holds a secret (pairing metadata; passkey metadata whose private key is in Keystore). Backup is fully excluded, so app-sandbox prefs are the right protection.

- [ ] **Step 1: Failing test.** Extend `IdentityPasskeyStoreTest.securityWipeClearsTheRecord` (or add `SecurityWipeTest` in androidTest) to also write `getSharedPreferences("mfa_push_challenge")` and `("push")` values plus a file named `pairing` in shared prefs, run `SecurityWipe.wipe`, and assert all are gone and `KeyStore` has no `_androidx_security_master_key_` alias.
- [ ] **Step 2: Implement.**
  - `PairingStore`: `context.getSharedPreferences("pairing_store", Context.MODE_PRIVATE)`; same keys and API. `IdentityPasskeyStore`: `"identity_passkey_store"`.
  - `SecurityWipe` step 1: after clearing the stores, `deleteSharedPreferences` for `"pairing_store"`, `"identity_passkey_store"`, legacy `"pairing"`, `"identity_passkey"`, `"kypasswords_pairing"`, plus `"mfa_push_challenge"` and `"push"`; step 5 also deletes alias `_androidx_security_master_key_`. Replace the `isAppAlias` KDoc sentence about androidx's master key with "androidx's master key is deleted by name in step 5; older builds used it for encrypted prefs."
  - `SecurityWipeAliasTest`: keep `!isAppAlias("_androidx_security_master_key_")` (the prefix sweep still does not match it; deletion is by name).
  - Remove the dependency; fix imports; delete `runCatching` wrappers whose only reason was ESP construction where the comment says so (keep wrappers that guard other failures).
- [ ] **Step 3: Run** the full check — Expected: PASS.
- [ ] **Step 4: AGENTS.md**: `pairing/` layout line drops "encrypted"; Deprecated platform APIs item drops `EncryptedSharedPreferences`/`MasterKey`; note that a wipe clears push challenge and token prefs.
- [ ] **Step 5: Commit** `refactor: plain app-private prefs replace EncryptedSharedPreferences`.

### Task B: androidx-built provider entries

Branch `refactor/provider-entries` from `main` after A merges.

**Files:**
- Modify: `app/build.gradle.kts` (add `androidx.credentials:credentials` — use the latest stable version; check Maven/`context7` docs)
- Modify: `app/src/main/java/org/kysecurity/authenticator/passkeys/CredentialSliceHelper.kt`
- Modify: `AGENTS.md`

- [ ] **Step 1: Check the API.** Confirm in current androidx.credentials docs that `androidx.credentials.provider.PublicKeyCredentialEntry` (with `.Builder(context, username, pendingIntent, beginGetPublicKeyCredentialOption)`) and `CreateEntry` expose a public `toSlice(entry)` (companion `@JvmStatic`) usable from a framework `android.service.credentials.CredentialProviderService`, and how to convert the framework `BeginGetCredentialOption` to the androidx option (`BeginGetPublicKeyCredentialOption.createFrom(...)` or `BeginGetCredentialOption.createFrom(id, type, candidateQueryData)`). Record the exact API and version in the report. **If `toSlice` is not public API, stop and report BLOCKED** — do not migrate the whole service.
- [ ] **Step 2: Implement.** `createGetCredentialEntry` builds a `PublicKeyCredentialEntry` (username = title, displayName = subtitle, same `PendingIntent` with `FLAG_MUTABLE or FLAG_UPDATE_CURRENT` and the same request code) and returns `android.service.credentials.CredentialEntry(option.id, PublicKeyCredentialEntry.toSlice(entry))`. `createCreateCredentialEntry` builds an androidx `CreateEntry(accountName = title, pendingIntent, description = subtitle)` and returns `android.service.credentials.CreateEntry(CreateEntry.toSlice(entry))`. Delete the custom `SliceSpec("kyauth", 1)` and every `Slice.Builder` use.
- [ ] **Step 3: Run** the full check — Expected: PASS; `grep -rn "Slice.Builder\|SliceSpec" app/src/main` prints nothing.
- [ ] **Step 4: AGENTS.md**: Deprecated platform APIs item: entries are built by androidx.credentials; note the selector rendering is unverified until seen on a device (add to Device verification).
- [ ] **Step 5: Commit** `refactor(passkeys): androidx.credentials builds the provider entries`.

### Task C: Split MainActivity

Branch `refactor/split-main-activity` from `main` after B merges.

**Files (create, each `internal fun MainActivity.…` extensions, the `UiComponents.kt` pattern):**
- `PairingFlow.kt`: `renderEnrollmentView`, `showPairingConfirmation`, `showManualPairingDialog`
- `LockScreen.kt`: `renderLockScreen`
- `VaultScreen.kt`: `renderTotpTab` (rename `renderVaultTab`), `updateTotpViews`, `showAddTotpOptionsDialog`, `scanTotpQr`, `showAddTotpDialog`, `showEditTotpDialog`, `showEditOrDeleteTotpDialog`
- `PushRequestCard.kt`: `renderPendingChallenge` plus one `respondToChallenge(challenge, approve: Boolean, digits: String)` replacing the duplicated `onNumberSelected`/`onDenyClicked` bodies
- `SettingsScreen.kt`: `renderSettingsTab`, `showSetPinDialog`, `showThemePicker`, `openCredentialProviderSettings`
- `AppChrome.kt`: `brand`, `kyAuthWordmark`, `bottomNavigation`, insets helpers, adaptive layout helpers
- `KyDialogs.kt`: `showKyDialog`, `dismissSensitiveDialogs`
- `SensitiveClipboard.kt`: `copyTotpCode`, `copySensitiveText`

`MainActivity.kt` keeps state fields, `Tab`, lifecycle, idle lock (`recordVaultActivity`, dispatch overrides), `renderContent`, dashboard shell, `unlockVault`/biometric unlock, TOTP load/save, `lockSensitiveState`, unpair/clear, AccountManager handoff, push load/permission.

- [ ] **Step 1: Make test-used members callable without reflection.** Change `pendingChallenge`, `openDialogs`, `renderContent`, `recordVaultActivity`, `showAddTotpDialog` to `internal` (fields stay fields). Update `VaultTabTest` and `LockClearsDialogsTest` to call/read them directly instead of `getDeclaredMethod`/`getDeclaredField` on `MainActivity` (AppLockManager reflection stays). Run `compileDebugAndroidTestSources` — PASS.
- [ ] **Step 2: Move code, one file per commit**, widening only what the moved code needs from `private` to `internal`. After each move run `./gradlew testDebugUnitTest compileDebugKotlin compileDebugAndroidTestSources`.
- [ ] **Step 3: Unify respond.** `respondToChallenge` builds the payload (approve: entered digits; deny: empty), runs the BiometricPrompt signing and `MfaResponseClient.respond`, and handles results exactly as the two old bodies did; drop the unused `account` parameter. Remove `numberButton` from `UiComponents.kt` (no callers). Replace raw-pixel `setPadding(48, 24, 48, 24)` in the PIN dialogs with `dp()`.
- [ ] **Step 4: Run** the full check — Expected: PASS. `wc -l MainActivity.kt` well under the original 1821.
- [ ] **Step 5: AGENTS.md** project layout lists the new files and what each owns.
- [ ] **Step 6: Commit** each move separately; final commit `refactor: split MainActivity by screen`.
