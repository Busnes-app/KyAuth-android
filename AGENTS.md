# KyAuth Android Client

KyAuth is the native Android authenticator for the KySecurity suite.

## Purpose

KyAuth pairs an Android device with KyIdentity. It stores TOTP entries in an encrypted local KDBX v4 vault. It also provides a local biometric and optional PIN lock.

## Current product contract

- Pairing accepts a short-lived KyIdentity QR payload or manual server details.
- Release builds require HTTPS. Debug builds permit loopback HTTP only.
- The optional registration URL must use the same origin as the pairing server.
- Each pairing generates a fresh P-256 device signing key (alias unchanged) with an attestation challenge derived from the pairing credential (`AttestationChallenge`), StrongBox first, TEE fallback, plain key when the device cannot attest. The registration request carries the attestation chain (`attestation`, base64 DER, leaf first); KyIdentity grades it `none`/`tee`/`strongbox` and returns `device.attestedLevel` and `device.bootState`, which `PairedAccount` stores and Settings shows, with an `attestationReason` (`AttestationReason`: server silent, keystore software-only, or chain not accepted) that lets the `none` hint say whether pairing again can help. Re-pairing rotates the key: the old key is deleted before registration, so a failed re-pair clears the local pairing and system account, because the phone has already deleted the key; the user pairs again. Unlike Unpair, it keeps the KyIdentity passkey. Settings shows the boot state on its own line. Only an attested device earns MFA-grade sign-on; see the attestation spec.
- Frozen identifiers, kept through the KyIdentity rename: the signed push prefix `kysignon-push-v1` (must equal what `kyidentity-server` `internal/mfa/mfa.go` verifies) and the Keystore alias `kysignon-device-signing-v1` (renaming it orphans every paired device's key). Rename nothing the server or the Keystore already holds.
- TOTP entries use KeePass `TimeOtp-*` fields in `totp_vault.kdbx`, along with standard KeePass title, URL, and notes.
- The TOTP vault uses an app-private file and an independent random vault key.
- The TOTP vault key is wrapped by `VaultKek`, an authentication-bound Keystore RSA-OAEP key
  (`setUserAuthenticationRequired(true)`, per-use), as `{"totp": base64}`. Wrapping needs no prompt;
  unwrapping requires a `BiometricPrompt.CryptoObject`. A device without a secure lock screen cannot
  use KyAuth.
- The app locks when it moves to the background. It clears in-memory TOTP data and its copied code,
  and zeroes the vault key arrays.
- The PIN is an optional second local factor. Failed PIN attempts use delays of 0, 5, 30, and 300 seconds. The fifth failure wipes local data.
- Release builds disable screenshots and Android backup.
- TOTP entries have no backup, export or sync, by decision: losing the phone loses its TOTP
  entries. KyIdentity access recovers through recovery codes or an admin MFA reset.
- Push MFA receives KyIdentity FCM data-message challenges, posts a local notification, and opens Vault, where the request card at the top approves or denies it. A response is only ever sent to the paired server; a `serverUrl` in the push payload is ignored. Digits must be two-digit, decoys are capped at 3, and expiry is clamped to 10 minutes.
- An MFA response must carry an explicit decision. A 2xx with no `approved`/`success` field is a protocol error, not an approval.
- A passkey whose RP ID is the paired KyIdentity server's host is the exception: its private key is
  generated in AndroidKeyStore (StrongBox where available, TEE otherwise), is non-exportable, and
  never enters a KDBX vault or any synced artifact. Only its metadata is stored, in
  `IdentityPasskeyStore`. The assertion path never touches the vault key, so KyIdentity
  MFA keeps working while KyAuth is locked. The Credential Provider offers it whether or not KyAuth
  is unlocked.
  Losing the device means falling back to KyIdentity recovery codes or an admin MFA reset.
- Passkeys use native ES256 / P-256 WebAuthn cryptography with COSE public key encoding and ECDSA assertion signing.
- KyAuth is an Android 14+ (API 34+) system Credential Provider for one credential: the KyIdentity
  login passkey (`KyAuthCredentialProviderService`, `CredentialAuthActivity`). It mints a passkey only
  for the exact paired KyIdentity host (`identityCreateTarget`), checked before any network work.
- Passkey RP IDs are validated by `RpId`: syntactically valid, not a public suffix, and for browser
  callers equal to or a registrable parent of the caller's web origin. Native-app callers are bound
  to the RP by `DigitalAssetLinks`, which fetches `https://<rpId>/.well-known/assetlinks.json` and
  matches the caller's signing certificate. It fails closed: no statement, or an offline device with
  a cold cache, means no passkeys are offered to a native caller.
- A caller-supplied `clientDataHash` is honoured only from a caller that set a privileged web origin
  (`ClientData.privilegedClientDataHash`). Only a holder of `CREDENTIAL_MANAGER_SET_ORIGIN` can set
  that origin, so an ordinary app cannot choose the bytes KyAuth signs. For every other caller the
  `CollectedClientData` is built here, with the `android:apk-key-hash:` origin.
- Foreground idle locking defaults to five minutes, configurable to 1/5/15/30/60 minutes in
  Settings. It uses elapsed realtime, includes dialog activity, and checks expiry before accepting
  new input. Background locking remains immediate. Lock generations reject stale asynchronous
  unlock/reveal results; only the UI thread installs loaded entry lists.
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
- `addAccount` serves only system Settings (`Process.SYSTEM_UID`) and pinned consumers
  (`mayAddAccount`); its result names the account, which only they may see. It hands
  `MainActivity` a `PendingAddAccount` nonce, never the response itself, so a forged launch's
  response extra is ignored. Pairing success, or an existing pairing, completes it with the
  account, and `onDestroy` answers `ERROR_CODE_CANCELED` if still pending.

## UI contract

- Use the `KyAuth` name in user-visible text.
- Use the KyPost mail stamp with the KyAuth wordmark in the header and lock screen; keep the KyAuth launcher icon.
- Use the three-part bottom pill: Vault, lock shield, Settings.
- The Vault screen shows a pending Push MFA request at its top, then the TOTP list with a + icon to scan QR or add accounts manually with optional Website and Notes fields.
- Use the 17 suite themes from `ThemeManager`. The default is Busnes Light; preserve valid saved choices.
- Use rounded, flat buttons. Do not add elevation shadows to custom controls.

## Project layout

- `app/src/main/java/org/kysecurity/authenticator/MainActivity.kt`: app UI and workflows.
- `pairing/`: QR parsing, endpoint validation, pairing network client, device key, `AttestationChallenge`, and encrypted pairing store.
- `mfa/`: push challenge model, FCM receive service, signed payload, and response client.
- `security/`: lock state, PIN policy, `VaultKek` authentication-bound key wrapping, `VaultUnlockPrompt`, atomic file writes, and local wipe.
- `totp/`: TOTP parsing, generation, and KDBX persistence.
- `signon/`: `DeviceAssertion` (assertion builder), `TrustedConsumers` (caller pins),
  `KyIdentityAccount` (system account lifecycle), `KyIdentityAuthenticator` + service,
  `PendingSignOn`/`PendingAddAccount` (nonce handoffs), `SignOnActivity`, `TokenClient`.
- `passkeys/`: FIDO2 WebAuthn crypto engine, `ClientData` (CollectedClientData), `RpId` validation,
  `IdentityPasskey` routing plus its hardware key and metadata store, CredentialProviderService, entry
  builder, slice builder, auth activity, and `PublicSuffix`.
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
```

## Outstanding security work

Recorded so it is not mistaken for done:

- **Push MFA payload binding.** `MfaMessage.formatPayload` still signs only
  `prefix|challengeId|verb|digits`. Binding server origin, account, purpose and expiry needs a
  matching KyIdentity server change.
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
- **Device verification.** Emulator tests cover secure-lock-backed `VaultKek` creation and backup
  flags. Full biometric prompts and the per-use
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
- **Deprecated platform APIs.** `Slice` and `EncryptedSharedPreferences`/`MasterKey` are deprecated. Moving to `androidx.credentials` would remove
  most of the Slice usage.

## Child DOX Index

No child `AGENTS.md` files exist.

## Product icon

App/launcher assets use the Busnes.app-site Systems stamp family. Regenerate platform sizes from the matching master in `../Busnes.app-site`; preserve resource names and adaptive foreground safe margins. Header and lock-screen artwork use `icons/kypost.png` as `kypost_hero`; launcher assets remain KyAuth.
