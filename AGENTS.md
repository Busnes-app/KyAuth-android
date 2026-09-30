# KyAuth Android Client

KyAuth is the native Android authenticator for the KySecurity suite.

## Purpose

KyAuth pairs an Android device with KyIdentity. It stores TOTP entries in an encrypted local KDBX v4 vault. It also provides a local biometric and optional PIN lock.

## Current product contract

- Pairing accepts a short-lived KyIdentity QR payload or manual server details.
- Release builds require HTTPS. Debug builds permit loopback HTTP only.
- The optional registration URL must use the same origin as the pairing server.
- Each pairing generates a fresh P-256 device signing key (alias unchanged) with an attestation challenge derived from the pairing credential (`AttestationChallenge`), StrongBox first, TEE fallback, plain key when the device cannot attest. The registration request carries the attestation chain (`attestation`, base64 DER, leaf first); KyIdentity grades it `none`/`tee`/`strongbox` and returns `device.attestedLevel` and `device.bootState`, which `PairedAccount` stores and Settings shows. Re-pairing rotates the key: the old key is deleted before registration, so a failed re-pair clears the local pairing and system account (the Unpair path), because the phone has already deleted the key; the user pairs again. Settings shows the boot state on its own line. Only an attested device earns MFA-grade sign-on; see the attestation spec.
- Frozen identifiers, kept through the KyIdentity rename: the signed push prefix `kysignon-push-v1` (must equal what `kyidentity-server` `internal/mfa/mfa.go` verifies) and the Keystore alias `kysignon-device-signing-v1` (renaming it orphans every paired device's key). Rename nothing the server or the Keystore already holds.
- TOTP entries use KeePass `TimeOtp-*` fields in `totp_vault.kdbx`, along with standard KeePass title, URL, and notes.
- The TOTP vault uses an app-private file and an independent random vault key.
- Both vault keys are wrapped by `VaultKek`, an authentication-bound Keystore RSA-OAEP key
  (`setUserAuthenticationRequired(true)`, per-use). Wrapping needs no prompt; unwrapping requires a
  `BiometricPrompt.CryptoObject`. A device without a secure lock screen cannot use KyAuth.
- One authentication yields one unwrap, so both keys share a single wrapped blob.
- The app locks when it moves to the background. It clears in-memory TOTP data and its copied code,
  and zeroes the vault key arrays.
- The PIN is an optional second local factor. Failed PIN attempts use delays of 0, 5, 30, and 300 seconds. The fifth failure wipes local data.
- Release builds disable screenshots and Android backup.
- Push MFA receives KyIdentity FCM data-message challenges, posts a local notification, and opens the Push MFA tab for approve/deny. A response is only ever sent to the paired server; a `serverUrl` in the push payload is ignored. Digits must be two-digit, decoys are capped at 3, and expiry is clamped to 10 minutes.
- An MFA response must carry an explicit decision. A 2xx with no `approved`/`success` field is a protocol error, not an approval.
- The KyPasswords key envelope must declare `kdf: argon2id`, and derivation uses the envelope's own
  `memoryKiB`/`iterations`/`parallelism` (Argon2id v1.3). Any other value, including a missing
  field, is refused rather than guessed at: the superseded PBKDF2 shape marked itself by omitting
  `kdf`, and with no KyPasswords deployment holding one, no envelope of that shape exists to read.
  Costs are server-supplied, so they are range-checked before anything is allocated (256 MiB
  ceiling) and rejected, not clamped. KyAuth writes the OWASP baseline (64 MiB, t=3, p=1).
- KDBX entry fields use the KeePass wire names from kotpass's `BasicField.key`, not the enum
  constant `name`. The two differ only for the URL field (`URL` vs `Url`); KyAuth used the constant,
  so its URLs were invisible to KeePassXC, KeePassDX and the KyPasswords web client, and theirs to
  KyAuth. Proven by `kypasswords-web-vault.kdbx`, a fixture written by kdbxweb.
- Passwords and Passkeys use `passwords_vault.kdbx`. The app can generate an independent random local vault key for device-only storage. Pairing with an empty KyPasswords account uploads that local vault with a client-created password envelope; pairing never replaces an existing server vault that uses another key.
- A passkey whose RP ID is the paired KyIdentity server's host is the exception: its private key is
  generated in AndroidKeyStore (StrongBox where available, TEE otherwise), is non-exportable, and
  never enters a KDBX vault or any synced artifact. Only its metadata is stored, in
  `IdentityPasskeyStore`. The assertion path never calls `AppLockManager.useVaultKeys`, so KyIdentity
  MFA keeps working while the password vault is locked, compromised, or in recovery. The Credential
  Provider therefore offers this one entry while KyAuth is locked, alongside the unlock action.
  Losing the device means falling back to KyIdentity recovery codes or an admin MFA reset.
- Passkeys use native ES256 / P-256 WebAuthn cryptography with COSE public key encoding and ECDSA assertion signing.
- KyAuth acts as an Android 14+ (API 34+) system Credential Provider for both Passkeys and Passwords via `KyAuthCredentialProviderService` (with `CredentialAuthActivity`) and an Android 12+ (API 31+) system Autofill Service via `KyAuthAutofillService`.
- While locked, neither provider touches vault material. Autofill returns a `FillResponse` with an
  authentication `IntentSender` (`AutofillUnlockActivity`). The Credential Provider returns an
  authentication `Action` (`CredentialUnlockActivity`) for anything vault-backed, and, when a
  KyIdentity passkey is enrolled, a real credential entry for it directly alongside that action — the
  passkey entry needs no vault key, which is why it can be offered while locked. The vault-backed
  paths unwrap the keys for one operation via `AppLockManager.useVaultKeys` and erase them again, so
  a background request never unlocks the app.
- Passkey RP IDs are validated by `RpId`: syntactically valid, not a public suffix, and for browser
  callers equal to or a registrable parent of the caller's web origin. Native-app callers are bound
  to the RP by `DigitalAssetLinks`, which fetches `https://<rpId>/.well-known/assetlinks.json` and
  matches the caller's signing certificate. It fails closed: no statement, or an offline device with
  a cold cache, means no passkeys are offered to a native caller.
- A caller-supplied `clientDataHash` is honoured only from a caller that set a privileged web origin
  (`ClientData.privilegedClientDataHash`). Only a holder of `CREDENTIAL_MANAGER_SET_ORIGIN` can set
  that origin, so an ordinary app cannot choose the bytes KyAuth signs. For every other caller the
  `CollectedClientData` is built here, with the `android:apk-key-hash:` origin.
- Autofill believes a request's `webDomain` only from a known browser installed as a system app or
  by Google Play; any other
  caller is matched on its own package. `setWebDomain` is public API, so an unfiltered domain from an
  arbitrary app would hand one site's credential to another.
- Password fill matches an entry's domain or its subdomains, never a parent or sibling, and never
  across a public suffix. Passkey matching is exact on RP ID.
- Incremental password/passkey edits use `KdbxPasswordVault.update`; delete uses its serialized
  `delete` operation. Both mutate the decoded KDBX by UUID, retaining groups, unknown fields,
  attachments, history and metadata. `saveEntries` only creates a new file. Existing empty or
  unreadable files fail closed. Live reads exclude the metadata-identified recycle bin and its
  descendants. Disabled recycling requires explicit permanent-delete confirmation. User edits
  honor the file's history item/content-size budgets; signCount-only updates add no history.
  Password vault reads and mutations run on worker threads; only their results reach the UI.
- `KyPasswordVaultSync` serializes sync sessions and uploads immutable encrypted snapshots.
  Downloads are decoded before installation under the local vault monitor. A remote replacement
  requires an unchanged local file and a known clean sync fingerprint. Unknown or dirty state,
  concurrent local writes and HTTP 409 preserve encrypted versions in `password-vault-conflicts`
  and surface a conflict; they never merge UI projections or automatically overwrite either side.
  Byte-identical local/remote files establish a missing baseline on upgrade. Explicit resolution
  chooses the whole device or server vault, guarded by If-Match and local-change detection.
  Clean successful syncs and unpairing remove conflict copies; startup/sync sweeps interrupted
  snapshots. Unpair clears the account, key and files in one vault transaction, so a new local
  vault cannot overtake teardown. A validated master-password key is adopted before sync, so network errors leave
  local access and conflict resolution available.
  Passwords can export those files; revealing their opening key uses the existing authenticated offline-key flow. Local wipe
  removes the conflict files along with all app-private files.
- The Passwords tab supports pairing with KyPasswords, syncing vaults, local add, generate, list, reveal, copy, and delete actions with distinct Passkey badging. Reveal and copy require a biometric or device-authentication prompt.
- The Passwords Recycle Bin is a metadata-only deleted-entry view, including descendants and
  untitled/non-password records. Restore moves the intact original entry to the live root; it
  preserves the UUID and all contents. There is no purge action. App lock clears and dismisses
  open dialogs, including unsaved forms and revealed secrets.
- Reused passwords compares exact nonempty strings across all live KDBX records, including
  whitespace-only passwords and untitled records. Its results contain metadata and counts only;
  passwords are never logged or sent. Open recovery/reuse views refresh after vault reloads.
- Foreground idle locking defaults to five minutes, configurable to 1/5/15/30/60 minutes in
  Settings. It uses elapsed realtime, includes dialog activity, and checks expiry before accepting
  new input. Background locking remains immediate. Lock generations reject stale asynchronous
  unlock/reveal results; only the UI thread installs loaded entry lists.
- Copied passwords are marked sensitive and clear after 30 seconds or when KyAuth locks.
- KyAuth is the Android account authenticator for `org.kysecurity.identity` (`signon/`). The account
  exists iff the paired device has KyIdentity's `canSignOn` and a user id; its user data is `server_url`, `user_id`,
  `device_id`, never a secret. `customTokens` is on: AccountManager still adds the caller UID
  to every `getAuthToken`, but skips its own grant check and token store, so the `TrustedConsumers` pin is the sole gate. No `KEY_CUSTOM_TOKEN_EXPIRY` is returned: the system caches nothing and every `getAuthToken`
  costs one biometric (the ID token's `jti` is single-use at the consumer).
- `TrustedConsumers` pins caller package plus signing-certificate SHA-256 and fails closed; a shared
  UID must be fully pinned, and a package with multiple signers (`hasMultipleSigners`) fails closed. The manifest `<queries>` lists every pinned package (SDK 30+ hides others from `getPackagesForUid`/`getPackageInfo`); a test keeps the two in step. Every certificate in `signingCertificateHistory` must be in the pin set
  (`containsAll`), so a key rotation needs the old and new digests pinned together before KyPost can
  sign on again. `authTokenType` is the consumer server's KyIdentity `client_id`.
- The consumer passes the relay URL its user typed in the `getAuthToken` options under
  `org.kysecurity.identity.origin` (the only source of the origin). `DeviceAssertion.relayOrigin`
  normalises it to `https://host[:port]` via `java.net.URI`: scheme `https`, non-empty host, no
  userinfo; host lowercased, port 443 dropped, path/query/fragment ignored. Anything else is refused
  with `ERROR_CODE_BAD_ARGUMENTS` before any prompt. Input over 256 characters or an explicit port
  outside 1..65535 is refused. The binding is per origin: two relays sharing host and port but with
  different paths are one trust domain. Relay names must be ASCII/punycode.
  `decideSignOn` checks in order: caller pin, client id, origin, pairing. The assertion carries it as
  the `origin` claim; KyIdentity checks it against the client's registered redirect-URI origins, so
  a pinned consumer cannot obtain a token for another relay's `client_id`.
- `SignOnActivity` is exported because AccountManager starts it from the requesting app's process.
  `getAuthToken` verifies the caller, then puts only the authenticator response and a single-use 120 s
  `PendingSignOn` nonce in the intent; no caller-describing extras exist. The activity takes the nonce
  once and, without one, answers the response with `ERROR_CODE_CANCELED` ("Sign-in request expired") and finishes with no UI, re-reads the pairing, shows "<app> at <relay host[:port]> wants to sign in as <user> at <KyIdentity host>.", takes one
  biometric through `VaultUnlockPrompt.showForSignature` on `DeviceSigningKey` (no vault key, so it
  works while locked), signs an RFC 7523 assertion (`DeviceAssertion`, `aud` is the trimmed
  `server_url` + `/oauth/token`; 8 claims including `origin`), redeems it (`TokenClient`) and returns the ID token once.
- KyIdentity side (shipped): the grant needs both `canSignOn` and MFA-approver on the device; an admin
  MFA reset ends sign-on; `device_signon_disabled` and `signon_not_permitted` (policy refuses: organisation MFA on an unattested device, app factor
  or fresh-password policy, or no app access) are returned only after the signature verifies. KyIdentity decides on every
  request: the local `canSignOn` is the value captured at pairing and is never cleared by a server
  refusal; the caller gets the message telling the user to turn sign-in on at the KyIdentity devices page, or for
  `signon_not_permitted` "This account cannot sign in to apps from this phone right now. Use web sign-in." The server accepts assertions up to 300 s
  old; KyAuth's window is 120 s.
- Settings shows the sign-on state and a "Restore system account" action when the account is missing;
  `KyIdentityAccount.sync` returns false if the system refused to add it and Settings says so.
- `addAccount` launches `MainActivity` with the authenticator response; pairing success completes it
  with the account, and `onDestroy` answers `ERROR_CODE_CANCELED` if still pending.

## UI contract

- Passwords offers passkey QR scanning on Android 14+. It accepts bounded `FIDO:/` digit URIs
  and explicitly hands them to Google Play services for hybrid transport and proximity checks;
  the existing Credential Provider handles authentication. KyAuth must be enabled as a provider.
  End-to-end QR sign-in still needs verification with a physical phone and nearby desktop browser.

- Use the `KyAuth` name in user-visible text.
- Use the KyPost mail stamp with the KyAuth wordmark in the header and lock screen; keep the KyAuth launcher icon.
- Use the five-part bottom pill: TOTP Vault, Push MFA, lock shield, Passwords, Settings.
- The TOTP Vault screen provides a + icon to scan QR or add accounts manually with optional Website and Notes fields.
- Use the 17 suite themes from `ThemeManager`. The default is Busnes Light; preserve valid saved choices.
- Use rounded, flat buttons. Do not add elevation shadows to custom controls.

## Project layout

- `app/src/main/java/org/kysecurity/authenticator/MainActivity.kt`: app UI and workflows.
- `pairing/`: QR parsing, endpoint validation, pairing network client, device key, `AttestationChallenge`, and encrypted pairing store.
- `mfa/`: push challenge model, FCM receive service, signed payload, and response client.
- `security/`: lock state, PIN policy, `VaultKek` authentication-bound key wrapping, `VaultUnlockPrompt`, atomic file writes, and local wipe.
- `totp/`: TOTP parsing, generation, and KDBX persistence.
- `passwords/`: password/passkey entry models, domain matcher, password generator, autofill service, and KDBX persistence.
- `signon/`: `DeviceAssertion` (assertion builder), `TrustedConsumers` (caller pins),
  `KyIdentityAccount` (system account lifecycle), `KyIdentityAuthenticator` + service,
  `PendingSignOn` (nonce handoff), `SignOnActivity`, `TokenClient`.
- `passkeys/`: FIDO2 WebAuthn crypto engine, `ClientData` (CollectedClientData), `RpId` validation,
  `IdentityPasskey` routing plus its hardware key and metadata store, CredentialProviderService, entry
  builder, slice builder, unlock activity, and auth activity.
- `ThemeManager.kt`: the shared 17-theme palette and local theme preference.
- `UiComponents.kt`: reusable programmatic view styling and controls.
- `AboutDialog.kt`: MIT About dialog.

## Work guidance

- Use the smallest correct change.
- Reuse native Android APIs and existing project code before adding dependencies.
- Fix shared root causes, not one call site.
- Keep security checks fail-closed.
- Add a focused test for non-trivial logic.
- Update this file when a durable product contract, workflow, or file boundary changes.

## Verification

Run unit tests, lint, the debug build, and compile device tests:

```bash
./gradlew test lintDebug assembleDebug compileDebugAndroidTestSources
npm ci --prefix tools --ignore-scripts
pip install argon2-cffi==25.1.0
node tools/vault_preservation.js app/build/interop
```

`KdbxPreservationTest` writes the Android round-trip outputs consumed by the Node verifier.
Regenerate the fake-secret rich fixtures with `node tools/vault_preservation.js generate`.

## Outstanding security work

Recorded so it is not mistaken for done:

- **Non-Play browser builds.** `TrustedBrowsers` accepts known browser packages only when installed
  by Google Play or as system apps. F-Droid and direct-download builds fail closed until explicit
  signing-certificate pins are maintained for them.
- **Vault size ceilings.** `KyPasswordClient` and `KdbxPasswordVault` cap a synced vault at 25 MB and
  a JSON body at 1 MB. Large legitimate vaults would need these raised.
- **Push MFA payload binding.** `MfaMessage.formatPayload` still signs only
  `prefix|challengeId|verb|digits`. Binding server origin, account, purpose and expiry needs a
  matching KyIdentity server change.
- **Non-KyIdentity passkey private keys are exportable.** Deliberate: they live in the KDBX vault so
  they sync and restore, as other password managers do. Protection comes from the
  authentication-bound vault key. The KyIdentity login passkey is the exception and is
  hardware-resident; see the product contract above.
- **Device key attestation positive path unverified.** Emulators ship software KeyMint, so `DeviceSigningKeyAttestationTest` only proves a chain exists and attests the pairing challenge; the server grades it `none`. No real-hardware pairing has been observed. A physical phone paired against a KyIdentity with the attestation verifier is what proves `tee`/`strongbox`. The test uses the production Keystore alias and deletes it: run it only on an unpaired device, or re-pair afterwards. The KyIdentity passkey (`IdentityPasskeyKey`) still has no attestation; the same challenge mechanism could extend to it.
- **KyIdentity passkey hardware backing is unverified.** `IdentityPasskeyKey.generate` accepts a key
  only when `KeyInfo.securityLevel` is `TRUSTED_ENVIRONMENT`, `STRONGBOX` or `UNKNOWN_SECURE`, so
  both `SOFTWARE` and `UNKNOWN` ("the platform could not tell") are refused; the fail-closed path
  is covered by a passing instrumented test. The positive path is not: every available Android
  emulator ships the software KeyMint reference implementation, so `generate` returning a
  hardware-backed key has never been observed succeeding. Four instrumented tests in
  `IdentityPasskeyKeyTest` are gated behind a JUnit assumption and SKIP rather than pass. Running
  them on a physical device is what closes this; until then, do not claim the key is
  hardware-resident.
- **Credential picker accumulation is unverified.** While locked, the provider returns the KyIdentity
  entry alongside the unlock action, and `CredentialUnlockActivity` deliberately passes
  `identityPasskey = null` so the entry is not duplicated after unlocking. That is correct only if the
  framework ADDS an authentication action's entries to those already shown rather than replacing
  them. This was decided by reading AOSP, not by observation. Verify on a device: with KyAuth locked,
  trigger a KyIdentity sign-in, tap "Unlock KyAuth", and confirm the KyIdentity passkey is still offered.
  If it disappears, pass the record through in `CredentialUnlockActivity` instead of null.
- **Device verification.** Emulator tests cover secure-lock-backed `VaultKek` creation and backup
  flags. Full biometric prompts, `useVaultKeys`, provider unlock flows, and the per-use
  `BiometricPrompt` for the KyIdentity passkey (enrolment and assertion, via
  `VaultUnlockPrompt.showForSignature`) still require manual device verification; none of these are
  currently automated here.
- **Consumer pins.** `TrustedConsumers.PINS` holds only `org.kysecurity.mail` (Play App Signing
  certificate). The GitHub flavor `org.kysecurity.mail.github` is unpinned until its upload-key digest
  is supplied, and `org.kysecurity.mail.fdroid` is unpinned because F-Droid signs with its own key and
  the digest does not exist until F-Droid builds it; both fail closed. Every certificate in a
  package's signing history must be pinned, so a key rotation needs old and new digests pinned
  together. Debug builds also accept `kyauthDebugConsumerCert`.
- **Late sign-on launch.** A `SignOnActivity` launch more than 120 s after its nonce was issued (or a
  replay) shows no UI and returns `ERROR_CODE_CANCELED` to the caller.
- **Sign-on device verification.** Unverified until observed on hardware: the full prompt; cancelling
  the biometric returns `ERROR_CODE_CANCELED` without a network call; account visibility for a
  consumer installed after the account was created; Settings -> Accounts removal followed by
  "Restore system account"; `getAuthToken` from KyPost launching the exported activity from KyPost's
  process; rotating the device mid-prompt keeps the prompt; a launch after the 120 s nonce expiry
  returns CANCELED to the caller; rotating the device during pairing keeps the addAccount request alive. Do not claim these until observed.
- **Deprecated platform APIs.** `Slice`, `EncryptedSharedPreferences`/`MasterKey`, and the
  `Dataset`/`FillResponse` builders are deprecated. Moving to `androidx.credentials` would remove
  most of the Slice usage.

## Child DOX Index

No child `AGENTS.md` files exist.

## Product icon

App/launcher assets use the Busnes.app-site Systems stamp family. Regenerate platform sizes from the matching master in `../Busnes.app-site`; preserve resource names and adaptive foreground safe margins. Header and lock-screen artwork use `icons/kypost.png` as `kypost_hero`; launcher assets remain KyAuth.
