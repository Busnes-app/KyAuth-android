# One KyIdentity login for suite apps via Android AccountManager

Date: 2026-09-29
Status: draft, awaiting review

## Problem

Every suite Android app signs in on its own. `kypost-android` pairs as a device (QR or
username+password → `pairingToken` → `deviceId`/`deviceSecret` headers). KyAuth pairs with
KyIdentity as a push-MFA approver. Vault, Messages and the coming Calendar will each want a
login too. The goal is one KyIdentity login on the phone, held by KyAuth, that the other apps
consume through the platform `AccountManager`, starting with KyPost.

## What exists today (measured, not assumed)

- **KyAuth pairing** registers a hardware P-256 key (`kysignon-device-signing-v1`, biometric
  or device credential on every use) at `POST /api/notifications/native/register`. KyIdentity
  stores it in `native_devices` linked to one `user_id`, flagged `is_mfa_approver`. The device
  has no token, no session and no OAuth role. `PairingStore` keeps `server_url`, `device_id`,
  `user_id`, `username`.
- **KyIdentity** is an OIDC provider with authorization-code + PKCE only. ID and access tokens
  are RS256 JWTs bound to a login session (`sid`, `EnsureClientSession`). No refresh tokens, no
  introspection, no device grant, no token exchange.
- **kypost-server, KyVault-server, KyMessage-Server** already trust KyIdentity by verifying its
  ID tokens (go-oidc / `ky-primitives/oidcverify`) and minting their own session from the
  claims (`sso_handlers.go:458`, `resolveSSOUser`). Mail routes accept a session cookie or the
  device headers (`withMailAuth`). Registration mints `deviceSecret`
  (`server_notifications.go:700`).
- **kypost-android** already ships an `AbstractAccountAuthenticator`, but only as a contacts
  sync owner (`KyPostContactAuthenticator`, account type `${applicationId}.contacts`,
  `getAuthToken` throws). Three flavors, three signing keys (Play App Signing, upload key,
  F-Droid). KyAuth and KyPost do not share a signing key, so signature-level permissions are
  not available between them.

## Decision

KyAuth becomes the Android account authenticator for account type `org.kysecurity.identity`.
An account is created when a paired device has the new server-side **sign-on** capability. A
consumer app asks `AccountManager` for a token; KyAuth verifies the caller's signing
certificate, shows one biometric prompt, signs a short-lived assertion with the existing
device key, and redeems it at KyIdentity for an ID token whose audience is the consumer's
server. The consumer app hands that ID token to its own server once, which verifies it exactly
as it verifies web SSO today and mints the credential it already uses (for KyPost:
`deviceId`/`deviceSecret`). The ID token is never stored on the phone.

One biometric per app link. No new long-lived secret on the phone: the device key is the
credential, as it already is for MFA.

### Rejected alternatives

**Browser OIDC code flow in each app (AppAuth / Custom Tabs).** Standard and needs no KyAuth
change, but it is a separate login per app in a browser, which is the thing being replaced.
Also weaker binding: no hardware key, no per-use biometric.

**Refresh tokens stored in KyAuth, handed out as bearer tokens.** Needs refresh tokens added to
KyIdentity, puts a long-lived bearer secret in AccountManager storage, and every consumer
server would have to grow bearer-token auth beside its session model. The device key already
is a durable, hardware-bound, biometric-gated credential; use it.

**A shared Android signing key so apps can use signature permissions.** Impossible with Play
App Signing and F-Droid re-signing, and it would couple release pipelines. Certificate pinning
inside the authenticator gives the same property without it.

## Design

### 1. KyIdentity server: sign-on capability and a device grant

- `native_devices.can_sign_on BOOLEAN NOT NULL DEFAULT 0`. Existing devices stay MFA-only.
- `POST /api/user/devices/pairing-token` takes `{"signOn": true|false}` from the browser
  page. The pairing-token row remembers it. Default in the UI is on: the page is already
  behind a step-up grant, and the device already holds a passkey that can log in alone, so
  sign-on is not an escalation beyond what the device can do today. The registration response
  adds `device.canSignOn`. The client cannot request the capability; only the token row grants
  it.
- Per-device toggle `PUT /api/notifications/native/devices/{id}/sign-on`, session-authenticated,
  no step-up, mirroring the existing `.../mfa` toggle. Enabling needs an MFA-approver device
  (409 `device_not_approver`); disabling is always allowed. An MFA reset clears `can_sign_on`. The devices page shows both switches.
  `DELETE /api/user/devices/{id}` keeps working and ends sign-on with it.
- `POST /oauth/token` accepts `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` (RFC
  7523) with `assertion` (compact JWS, `alg=ES256`) and `client_id`. The assertion is the
  client authentication; `client_secret` is not required for this grant.
  - Header: `{"alg":"ES256","typ":"JWT","kid":"<device_id>"}`.
  - Claims: `iss` = `device:<device_id>`, `sub` = user id, `aud` = the issuer's token
    endpoint URL, `client_id` = target client (bound inside the signature so a captured
    assertion cannot be redirected), `iat`, `exp` ≤ `iat`+300, `jti` (random, single-use).
  - Server checks, in order: `aud`, `exp`, clock skew 60 s; device exists and belongs to
    `sub`; ES256 signature with that device's public key only (not "any key the user owns",
    the gap the push verifier has); then `can_sign_on` AND `is_mfa_approver` (after the
    signature, so `device_signon_disabled` only reaches the key holder); `jti` unused (store with expiry); `client_id`
    registered and equal to the form `client_id`; user active and not disabled by SCIM; the
    client's app authentication policy, enforced as the code grant does.
  - On success: create a login session for the user with method `device` (so `sid`,
    `EnsureClientSession`, back-channel logout and `LoggedOut` checks keep working), issue an
    ID token and access token with the normal shape plus
    `amr: ["pop"]`, `acr urn:kysignon:acr:device`, `auth_time` = now,
    `signon_method: "device"`, `device_id`. Device sign-on is single-factor: the session
    carries `PrimaryAuthenticatedAt` = now and no factor evidence, because enrollment accepts
    any P-256 key and nothing proves hardware backing or user verification. The existing
    enrollment guard (`mfa_session_access`) therefore refuses users whose policy requires MFA,
    and app policies that require a factor refuse; neither special-cases devices. No refresh token. Audit `device_signon` success
    and failure with device id and client id. Update `last_seen_at`.
  - Rate limit as `device_signon`, 10 burst, 0.2/s per IP, inside the route's `oauth_token` limiter.

### 2. KyAuth: the authenticator

New package `signon/`:

- `KyIdentityAuthenticator : AbstractAccountAuthenticator`, exported service with the
  `android.accounts.AccountAuthenticator` filter, `res/xml/kyidentity_authenticator.xml` with
  `android:customTokens="true"` so the system never caches tokens and every request reaches
  KyAuth with `KEY_CALLER_UID`.
- Account: name = `username`, type `org.kysecurity.identity`, password `null`, user data
  `server_url`, `user_id`, `device_id`. No secret ever goes into AccountManager user data.
- `addAccount` (Settings → Accounts → Add, or a consumer calling it): returns `KEY_INTENT` to
  `MainActivity`'s existing pairing flow. Pairing success with `canSignOn` calls
  `addAccountExplicitly` and sets `VISIBILITY_VISIBLE` for every pinned consumer package.
  Unpair and local wipe call `removeAccountExplicitly`. Removing the account from system
  Settings removes only the account; the device stays paired for MFA and KyAuth offers to
  re-create the account from Settings.
- `getAuthToken(account, authTokenType, options)`:
  1. Resolve `KEY_CALLER_UID` → package(s) → signing certificates. Compare against
     `TrustedConsumers`: a static map of package name → set of SHA-256 certificate digests.
     Unknown package or unknown certificate → `ERROR_CODE_UNSUPPORTED_OPERATION`, audited. This
     is the trust boundary; account visibility is convenience only.
  2. `authTokenType` is the consumer server's KyIdentity `client_id`. Must match
     `[A-Za-z0-9._:-]{1,128}`.
  3. Return `KEY_INTENT` to `SignOnActivity`: "**KyPost** wants to sign in as **yoshi** at
     **id.example.com**", Approve/Deny. Approve runs the device-key `BiometricPrompt`
     (existing `DeviceSigningKey` path), builds the assertion, converts the DER signature to
     raw `r||s`, posts the grant, and delivers `KEY_AUTHTOKEN` = ID token with
     `KEY_CUSTOM_TOKEN_EXPIRY` = its `exp`. Deny or any error returns
     `ERROR_CODE_CANCELED` / `ERROR_CODE_REMOTE_EXCEPTION` with a user-readable message; the
     server's `device_signon_disabled` error tells the user to re-enable sign-on on the
     KyIdentity devices page.
  4. The device key is independent of `VaultKek`, so sign-on works while KyAuth's vault is
     locked, the same way the KyIdentity passkey does.
- `invalidateAuthToken`, `confirmCredentials`, `updateCredentials`, `editProperties`: no-ops.
  `hasFeatures` answers `signon` true.
- `TrustedConsumers` holds release digests only. Debug builds additionally accept the digest in
  the Gradle property `kyauthDebugConsumerCert`, never a hardcoded debug key. Adding a suite
  app is one line here plus its server's exchange endpoint.
- Domain separation from push responses is by construction: a JWS begins with `eyJ`; push
  messages begin with `kysignon-push-v1|`.

### 3. kypost-server: accept the token once

- `GET /api/auth/sso-config` (exists, public) gains `clientId` beside `enabled` and `issuerUrl`.
  Both values are public in OIDC.
- `POST /api/auth/native/signon`, marked `withTokenAuth`, metered on the SSO per-IP limiter.
  Body `{idToken}`. A new `sso.Provider.VerifyIDToken` runs the same go-oidc verification
  `Exchange` runs (signature, issuer, audience, expiry, nbf, non-empty sub) minus the nonce and
  at_hash checks that only a browser code flow can make; require `signon_method == "device"`,
  `iat` within the last 5 minutes and `jti` single-use through the existing `singleUse` cache;
  then the same directory revocation, `resolveSSOUser`, active-user and `LoggedOut` checks the
  web callback runs. On success it answers exactly what `POST /api/notifications/review-pairing`
  answers: `writeNotificationPairing(w, user.ID)`, a single-use 90-second `kypost://native-pair`
  deep link with the pairing token, register endpoint and TLS pin.
- Nothing else changes. The device registers through `native/register` with that token as it
  does today, which mints the `deviceId`/`deviceSecret` pair, push transport, lockout and
  deregister behaviour unchanged. The `backend/AGENTS.md` rule that only `Exchange` accepts an
  ID token is amended to name `VerifyIDToken` and the one caller allowed to use it.

### 4. kypost-android: consume it

New `signon/` package, entered from a "Sign in with KyIdentity" button on the pairing screen:

1. `KyIdentitySignOnActivity` asks for the kypost-server URL, fetches `/api/auth/sso-config`,
   and stops with a message when `enabled` is false or `clientId` is empty.
2. `AccountManager.getAccountsByType("org.kysecurity.identity")`. None visible →
   `newChooseAccountIntent` restricted to the type (this also grants visibility). Still none →
   `addAccount`, which opens KyAuth pairing.
3. Before trusting the account, `AuthenticatorPin` checks `getAuthenticatorTypes()` for that
   type: the authenticator's package must be `org.kysecurity.authenticator` with a pinned KyAuth
   certificate. Anything else fails closed. (A rogue authenticator could never produce a token
   kypost-server accepts, but this stops it from phishing the prompt.)
4. Require the account's `server_url` to equal the config's `issuerUrl`.
5. `getAuthToken(account, clientId, null, activity, ...)`. KyAuth shows its prompt.
6. `POST /api/auth/native/signon` with the token; the reply is a deep link, parsed by the
   existing `NativePairingDeepLinkParser` and handed to `PushPairingActivity` exactly as
   `PasswordPairingActivity` does. The normal pipeline registers the push token, pins TLS and
   stores the device secret; no new coordinator or store path.

QR and password pairing stay for servers without SSO.

### 5. Security properties and what is proven

| Property | How | Verification |
|---|---|---|
| Only suite apps get tokens | Caller certificate pin in `getAuthToken` | Unit test on the pin check with a fake `PackageManager`; instrumented test that an unpinned caller is refused |
| A token for KyPost is useless at KyVault | `aud` = per-server `client_id`; `client_id` inside the signed assertion | Server test: wrong audience rejected |
| No replay | `jti` single-use at both KyIdentity and the consumer server; 5-minute `exp` | Server tests: second use rejected |
| Only the enrolled device signs | KyIdentity verifies against that device's key only | Server test: sibling device key rejected |
| Not claimed as MFA | Session has no factor evidence; `amr` is `["pop"]`, `acr` is `urn:kysignon:acr:device`; refused wherever MFA is mandatory | Server tests: MFA-required user and factor-requiring app policy refused, claims asserted |
| Revocable | `can_sign_on` toggle, device delete, MFA reset; live sessions and minted credentials are not revoked (see gaps) | Server tests |
| Nothing long-lived added to the phone | Token returned once, `customTokens` prevents system caching | Code review; KyPost stores only what it stores today |

Unproven until run on a physical device: the full prompt path, account visibility for a
package that is installed after the account was created, and Play App Signing certificate
digests. Record these in AGENTS.md "Outstanding security work" until observed.

### Known gaps carried, not fixed here

- `TrustedConsumers` needs the F-Droid signing digest for KyPost, which does not exist until
  F-Droid builds it. Same standing issue as `TrustedBrowsers`.
- A pinned consumer can request any `client_id`. All pinned apps are ours; a per-package
  audience allowlist would hardcode deployment-specific client ids. Accepted.
- Revoking sign-on does not revoke `deviceSecret`s already minted at kypost-server. Turning
  sign-on off or deleting the device does not end live device login sessions, and expired
  device sessions are swept without a back-channel logout, so consumers must not rely on
  back-channel logout for credentials minted from a device sign-on; they expire on the
  consumer's own schedule.
- Device sign-on is single-factor. Follow-up (Yoshi, 2026-09-30): attestation-gated MFA
  grade — KyAuth generates the device key with a server-issued attestation challenge at
  pairing and uploads the certificate chain; KyIdentity verifies it to Google's hardware
  attestation root (security level, per-use user auth, challenge match), stores the attested
  level, and only attested devices get MFA-grade sign-on. Until then device sign-on is refused
  wherever MFA is mandatory.

## Sequence and repos

1. **KyIdentity-server**: schema, sign-on toggle, pairing-token flag, JWT-bearer grant, tests.
2. **kyauth-android**: `signon/` package, manifest, pairing hook, `TrustedConsumers`,
   AGENTS.md contract update, unit and instrumented tests.
3. **kypost-server**: config and sign-on endpoints, tests.
4. **kypost-android**: `KyIdentitySignOn`, pairing screen button, authenticator pin, tests.
5. Device verification on a phone with all four deployed; then AGENTS.md closeout in each repo.

Vault, Messages and Calendar follow by repeating steps 3 and 4 and adding one pin line in
KyAuth.

## Assumptions to confirm

- One KyIdentity server per phone for now; multi-issuer accounts are out of scope.
- Sign-on defaults on for new pairings, revocable per device.
- Account type `org.kysecurity.identity` and the `Sign in with KyIdentity` label.
- The JWT-bearer grant lives on `/oauth/token` rather than a bespoke route.
