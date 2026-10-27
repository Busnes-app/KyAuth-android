# Assurance case

[Product overview](../README.md) · [Security](../SECURITY.md) · [Product contract](../AGENTS.md)

This is the argument that KyAuth meets its security requirements: what it protects, from whom,
where the trust boundaries are, and why the design and the code hold at each one. The detailed
contract is in [AGENTS.md](../AGENTS.md); this page ties it together and points at the evidence.
Paths are relative to `app/src/main/java/org/kysecurity/authenticator/` unless they start with
`app/` or `.github/`.

## What KyAuth must protect

KyAuth pairs an Android phone with a KyIdentity server. It answers push sign-in requests, holds
TOTP secrets and signs suite apps in. Its security requirements:

1. **Only this phone, in its owner's hand, approves a sign-in.** An approval needs the paired
   device key, and that key needs a fresh biometric or device-credential check every time.
2. **TOTP secrets stay secret** from other apps, from backups and from anyone who copies the app's
   files. Opening them needs the user.
3. **KyAuth talks only to the server it was paired with,** over HTTPS, and a hostile server or
   push message cannot make it approve something else.
4. **Only pinned suite apps get a sign-on token,** and only for the origin they asked about.
5. **Nothing secret leaks** to logs, screenshots, the recents screen, the clipboard history or an
   Android backup.
6. **Losing control fails closed.** Wrong PINs, a missing key or an unreadable vault lock the app
   or wipe it. They never fall back to something weaker.

## Threat model

| Attacker | Can | Wants |
|---|---|---|
| Hostile or spoofed KyIdentity server (from a crafted QR) | Answer KyAuth's requests | Hang or crash the app, steer it to another host, get a signature for another server |
| Network attacker | Read and alter traffic | Read or forge pairing, approvals or tokens |
| Push relay, Google FCM, UnifiedPush distributor | See and send push messages | Learn who signs in where, or forge a sign-in request |
| Another app on the phone | Call KyAuth's exported components and AccountManager | Get an ID token, read TOTP secrets, start a sign-in |
| Someone holding the phone, locked | Guess PINs, take screenshots or backups | Open the vault or approve a sign-in |
| Someone with a copy of the app's files | Read `totp_vault.bin` and preferences | Recover TOTP secrets |

Out of scope: a rooted or compromised phone, or an attacker who has the phone unlocked with
KyAuth open. Both are inside every boundary here. Server-side issues belong to
[KyIdentity](https://github.com/Busnes-app/KyIdentity-server).

## Trust boundaries

1. **KyAuth → KyIdentity.** One HTTP client, `pairing/ServerHttp.kt`, carries every request. The
   pairing, MFA response, push refresh, device revoke and token clients all call it, and nothing
   else opens a connection. It follows no redirects, caps a response at 64 KiB, and gives up after
   10 s to connect or read and 30 s overall. Release builds refuse any server or registration URL
   that is not `https`, and the registration URL must have the pairing server's origin
   (`pairing/PairingEndpoint.kt`).
   `pairing/ServerTls.kt` retains native socket-aware trust and hostname checks, then
   inspects the complete evaluated chain, including its anchor, for actual RSA-2048
   or EC-256 minimum keys. Unknown keys or an unavailable verified chain fail closed.
   This factory applies to app-owned requests only; SDK transports keep their own TLS.
2. **Push services → KyAuth.** Both push services hand data only to `mfa/IncomingPush.kt`. A sealed
   FCM push is decrypted with RFC 8291 (`mfa/WebPush.kt`) using keys only this pairing holds. A
   plaintext FCM push is accepted only while the pairing has no keys
   (`PushStore.acceptsPlaintextFcm`). A request must name this device and account, and must expire
   within 10 minutes (`MfaPushChallengeStore.MAX_EXPIRES_AFTER_MS`). An answer goes only to the
   paired server; a `serverUrl` in the push is ignored.
3. **Other apps → KyAuth.** `signon/TrustedConsumers.kt` pins each caller by package and
   signing-certificate SHA-256. Every certificate in the caller's signing history must be pinned
   (`containsAll`), and a package with multiple signers is refused. `SignOnActivity` is exported,
   but it acts only on a single-use nonce that expires after 120 s (`signon/PendingSignOn.kt`). The
   requested origin must be plain `https://host[:port]` (`DeviceAssertion.relayOrigin`).
4. **KyAuth → its own storage.** TOTP entries are AES-256-GCM encrypted in `totp_vault.bin`. The
   vault key is wrapped by an RSA-OAEP Keystore key that needs user authentication for every
   unwrap (`security/VaultKek.kt`).
5. **The user → KyAuth.** Biometric or device credential for every signature and every vault
   unlock. The optional PIN is a second local factor with a wipe after five failures.

## Secure design principles applied

- **Least privilege.** The device signing key is for signing and verifying only, and each use
  needs a fresh user check.
  FCM push keys are wrapped under their own Keystore key (`security/PushKeyWrap.kt`). The fdroid
  build carries no Google code, and CI proves it.
- **Fail-safe defaults.** A missing or unreadable vault file keeps KyAuth locked
  (`TotpVaultException`). An unpinned consumer is refused. A 2xx MFA response from the server with no
  explicit decision is a protocol error, not an approval (`mfa/MfaResponseClient.kt`). A request that has expired cannot be approved.
- **Complete mediation.** Each approval and each sign-on asks for its own biometric. The ID token
  is not cached (`customTokens`, no expiry returned).
- **Economy of mechanism.** Platform APIs only: `HttpURLConnection`, `org.json`, the Android
  Keystore, `javax.crypto`. Direct runtime dependencies are AndroidX, Material, Play code scanner
  and Firebase Messaging (play and github builds only), zxing (fdroid only) and the UnifiedPush
  connector (`app/build.gradle.kts`).
- **Separation of privilege.** The vault key and the device signing key are separate Keystore keys,
  each bound to user authentication. The optional PIN adds a second local factor.
- **Open design.** Only published algorithms: AES-256-GCM, RSA-OAEP, ECDSA P-256 with SHA-256,
  HMAC-SHA-256, PBKDF2-HMAC-SHA-256, RFC 6238 TOTP and RFC 8291 push encryption.
- **Psychological acceptability.** Trade-offs are written where users read them: no TOTP backup
  by design, and keyless FCM pairings staying plaintext until they reconnect
  ([README](../README.md#what-to-know-before-you-rely-on-it), [AGENTS.md](../AGENTS.md)).

## Common weaknesses and how they are countered

| Weakness | Counter | Where |
|---|---|---|
| Cleartext transport, downgrade | `https` required in release builds for the server and registration URLs; debug allows only loopback `http` | `pairing/PairingEndpoint.kt` |
| Redirect to another host | Redirects disabled on the one HTTP client | `pairing/ServerHttp.kt` (`instanceFollowRedirects = false`) |
| Undersized TLS certificate keys | Native trust validation followed by a full evaluated-chain key floor, including roots omitted from the wire; no hostname or pin override | `pairing/ServerTls.kt`; `ServerHttpTLSDeviceTest`; [native evidence and limits](native-tls-evidence.md) |
| Resource exhaustion from a hostile server | 64 KiB response cap, 10 s timeouts, 30 s overall deadline | `pairing/ServerHttp.kt` (`readBounded`) |
| Forged or replayed push request | RFC 8291 sealed FCM, plaintext refused once keys are registered, device and account must match, expiry at most 10 minutes ahead | `mfa/WebPush.kt`, `mfa/IncomingPush.kt`, `pairing/PushStore.kt` |
| Approval signed for the wrong context | The signed message binds origin, user, device, challenge, purpose and expiry | `mfa/MfaChallenge.kt` |
| Token theft by another app | Caller pinned by package and full signing history; single-use 120 s nonce; origin normalised before any prompt | `signon/TrustedConsumers.kt`, `signon/PendingSignOn.kt`, `signon/DeviceAssertion.kt` |
| Secrets at rest | AES-256-GCM vault, fresh 12-byte nonce from `SecureRandom` per save, AAD `kyauth-totp-v1`; vault key wrapped by an auth-bound RSA-2048 OAEP Keystore key | `totp/TotpVault.kt`, `security/VaultKek.kt` |
| Device key extraction | P-256 key in the Keystore, StrongBox first, then TEE; needs user authentication; attestation chain sent to KyIdentity | `pairing/DeviceSigningKey.kt` |
| PIN guessing | PBKDF2-HMAC-SHA-256 with 150,000 iterations and a 16-byte random salt, peppered with a Keystore HMAC key usable only while the phone is unlocked; delays of 0, 5, 30 and 300 s; wipe after the fifth failure | `security/CredentialCipher.kt`, `security/PinFailurePolicy.kt`, `security/AppLockManager.kt` |
| Weak randomness | Keys, salts and nonces come from `SecureRandom` or the Keystore. `kotlin.random` appears only in demo mode, which has no secrets | `security/CredentialCipher.kt`, `totp/TotpVault.kt`, `DemoMode.kt` |
| Secrets on screen or in backups | `FLAG_SECURE` on every window that can show a secret in release builds; `allowBackup="false"` | `security/SecureWindow.kt`, `MainActivity.kt`, `signon/SignOnActivity.kt`, `app/src/main/AndroidManifest.xml` |
| Secrets on the clipboard | A copied code is marked sensitive and cleared at the end of its period or on lock | `MainActivity.kt` (`EXTRA_IS_SENSITIVE`) |
| Undersized imported TOTP keys | QR/manual imports and changed secrets require at least 16 decoded bytes; generation refuses short keys for all HMAC choices. Legacy records remain stored and show issuer re-enrolment guidance, without a copyable code | `totp/TotpGenerator.kt`, `totp/TotpUriParser.kt`, `totp/TotpDisplay.kt`, `MainActivity.kt`; `TotpGeneratorTest`, `TotpVaultTest`, `VaultTabTest` |
| Secrets in logs | Four log calls in total. They log exception class names and dropped-message notices, never message contents | `pairing/DeviceSigningKey.kt`, `mfa/KyAuthUnifiedPushService.kt`, `app/src/gms/.../mfa/KyAuthMessagingService.kt` |
| Vulnerable dependencies | Dependabot for Gradle and Actions; dependency graph submission | `.github/dependabot.yml` |
| Supply-chain tampering | Actions pinned by commit SHA; the Gradle wrapper jar validated in every workflow; release APKs carry a build-provenance attestation | `.github/workflows/`, [VERIFYING-RELEASES.md](VERIFYING-RELEASES.md) |

## Residual risk

These are recorded, not hidden ([AGENTS.md, Outstanding security work](../AGENTS.md#outstanding-security-work)):

- The hardware-attestation positive path, the biometric prompts, sealed FCM on a real device,
  UnifiedPush delivery and the sign-on flow have not been observed on physical hardware.
- A pairing made before KyAuth sent push keys stays plaintext over FCM until its next Reconnect
  or re-pair.
- The GitHub and F-Droid builds of KyPost are not pinned, so they cannot sign on through KyAuth.
- Pairing trusts the QR code. Whoever controls the QR controls which server KyAuth pairs with.
  The server enforces the pairing token's 90-second lifetime. The client also refuses a QR whose
  `expiresAt` has passed, but it accepts one that has no `expiresAt`.

## Evidence

- **Tests:** JVM unit tests cover the parsers, policies, crypto wire formats
  and golden vectors (`WebPushTest` against RFC 8291 appendix A, `PushRefreshClientTest`).
  Instrumented tests cover Keystore, vault and UI behaviour. CI runs the unit tests for all three
  flavors and the complete Play/F-Droid instrumented suites on API 35 emulators on every push and pull request
  (`.github/workflows/android.yml`).
- **Static analysis:** CodeQL for Java/Kotlin on every push and pull request to `main` and weekly
  (`.github/workflows/codeql.yml`). Android Lint for all three flavors in CI. OpenSSF Scorecard.
- **Dynamic analysis:** the instrumented suite on an emulator. There is no fuzzing.
- **Review:** changes land through pull requests with green CI ([CONTRIBUTING.md](../CONTRIBUTING.md#pull-requests)).
- **Releases:** signed APKs with build-provenance attestations ([VERIFYING-RELEASES.md](VERIFYING-RELEASES.md)).

This case is updated when a trust boundary or a security requirement changes. A pull request that
moves one must update this page in the same change.
