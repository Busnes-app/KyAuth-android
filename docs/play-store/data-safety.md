# Play Console Data safety: KyAuth (`play` flavor)

Draft for `org.kysecurity.authenticator` 0.5.0 (versionCode 6). Grounded in the worktree at
`release-0.4.0` as of 2026-10-13, including its uncommitted changes. Paths are relative to
`app/src/` unless noted. "Unproven" means the claim was not tested against a built `playRelease` APK.

## Where data goes (play flavor)

| Destination | What the app sends | Trigger | Evidence |
| --- | --- | --- | --- |
| User's own KyIdentity server, `POST /api/notifications/native/register` | pairing token or PIN, userId, `Build.MODEL`, random installation UUID, platform, device public key, Key Attestation chain, push token + transport + WebPush keys (UnifiedPush endpoint URL, or FCM token and KyAuth's own FCM keys) | User scans QR / enters code, confirms, passes biometric | `main/.../MainActivity.kt:341-370`, `main/.../pairing/PairingClient.kt:88-109`, `main/.../pairing/PairingStore.kt:23` |
| KyIdentity, `PUT .../devices/{id}/push-token` | push token, transport, keys, timestamp, signature | User taps reconnect, biometric-gated | `main/.../MainActivity.kt:1204-1214`, `main/.../pairing/PushRefreshClient.kt:59-66` |
| KyIdentity, `POST /api/mfa/push/respond` | challengeId, server deviceId, selected digits, approve/deny, signature | User answers a sign-in request | `main/.../MainActivity.kt:1273`, `main/.../mfa/MfaResponseClient.kt:28-34` |
| KyIdentity, `POST /oauth/token` | signed JWT assertion (iss device:id, sub userId, client_id, aud, jti, origin) | Another app (KyPost) requests sign-on; user approves | `main/.../signon/SignOnActivity.kt:135`, `main/.../signon/DeviceAssertion.kt:41-50`, `main/.../signon/TokenClient.kt:47-51` |
| Google, Firebase Cloud Messaging + Firebase Installations | FID, FCM token, app version, device metadata (OS version, model, brand, form factor) | **Automatically at app start** (FCM auto-init is not disabled) | `gms/AndroidManifest.xml:5-11`, `gms/java/.../pairing/PushTokenProvider.kt:14`; no `firebase_messaging_auto_init_enabled` anywhere |
| Google Play services, code scanner (ML Kit) | device info, package name/version, per-installation ID, performance/diagnostics (per Google) | User taps Scan | `gms/java/.../ChannelQrScanner.kt:6-11` |
| UnifiedPush distributor (separate app chosen by user) | registration only, on device; the distributor's own server is outside this app | User picks "Use UnifiedPush" | `main/.../MainActivity.kt:1425-1432`, `main/.../mfa/KyAuthUnifiedPushService.kt:15-26` |
| Another app on device (KyPost) | KyIdentity ID token + account name via AccountManager | User-approved sign-on | `main/.../signon/SignOnActivity.kt:146-155` |

KyIdentity forwards FCM pushes through the FCM relay Worker the developer runs
(KyIdentity-server `workers/fcn`), so the developer receives the FCM token with every push. For a
pairing made with this build or refreshed since, the challenge is RFC 8291 sealed and the relay
sees only `type` and ciphertext; a pairing made before it still sends the challenge fields in
the clear until it refreshes (problem 5). The app never contacts the relay itself.

Since KyIdentity added it, a sealed challenge also carries the signing-in account's username,
which the request card shows. It is inside the RFC 8291 ciphertext only, so the relay and FCM
cannot read it, and KyIdentity never puts it in the plaintext form: KyAuth drops a `username` in a
plaintext push (`IncomingPush.fcmData`). It travels server to device, is kept with the pending
request in app-private prefs until answered or expired, and is never sent back. So the developer
receives no username and no new declaration is needed: this adds nothing to the Data types below.
The username saved at pairing (from the QR) was already on the device.

Nothing else leaves the device. The only `HttpURLConnection` users are the four KyIdentity
clients above (grep for `openConnection` under `main/` and `gms/`). TOTP secrets, the vault,
the PIN and biometric results stay local. Demo mode makes no network calls
(`main/.../DemoMode.kt:10`). The privacy-policy link is a user-initiated browser intent
(`main/.../AboutDialog.kt:71-73`).

## Play's definitions (support.google.com/googleplay/android-developer/answer/10787469)

Quotes as retrieved on 2026-10-13:

- Collect: "\"Collect\" means transmitting data from your app off a user's device." SDK traffic
  counts "irrespective of whether data is transmitted to you or a third-party server."
- Share: "\"Sharing\" refers to transferring user data collected from your app to a third party",
  including to another app on the device. Exempt: service providers, and transfers "based on a
  specific user-initiated action, where the user reasonably expects the data to be shared."
- Ephemeral: "accessing and using it while the data is only stored in memory" and "retained for no
  longer than necessary to service the specific request in real-time."
- Closest analogue to a self-hosted server is the cloud-storage FAQ: no declaration is needed when
  "the user chooses to upload their data directly to their own external drive or cloud storage
  account" **and** "your app never collects or accesses the data in question."
- Encryption in transit can be declared only "if it applies to all user data" the app sends.

### Recommendation on the self-hosted KyIdentity server

Declare it as collected. The definition turns on transmission off the device, not on who
receives the data. The cloud-storage exemption needs "your app never collects or accesses the
data", and here KyAuth itself builds and sends the payload. Declaring also costs nothing: FCM
already forces "collects data: Yes" and "Device or other IDs". Declare it as **not shared**: the
user picks and runs the server and starts every transfer, so the user-initiated exemption fits
better than calling the server a third party. Explain the self-hosted model in the privacy policy.

## Top-level questions

| Question | Answer | Evidence |
| --- | --- | --- |
| Does your app collect or share any of the required user data types? | **Yes** | FCM/Installations always collect FID and device metadata (Firebase disclosure, below); KyIdentity pairing sends IDs (`PairingClient.kt:88-109`) |
| Is all user data encrypted in transit? | **Yes** | Release builds accept only `https` server and registration URLs (`main/.../pairing/PairingEndpoint.kt:12,32`; http only when `BuildConfig.DEBUG` + loopback); redirects off (`PairingClient.kt:30`, `TokenClient.kt:30`, `MfaResponseClient.kt:41`, `PushRefreshClient.kt:23`); cleartext config is debug-only (`debug/AndroidManifest.xml:2`); Firebase: "Firebase encrypts the data in transit using HTTPS"; ML Kit: "encrypts the data in transit using HTTPS". UnifiedPush pushes, and FCM pushes to a pairing with keys, are also RFC 8291 encrypted end to end (`KyAuthUnifiedPushService.kt`, `main/.../mfa/WebPush.kt`, `IncomingPush.fcmData`); that is on top of transport encryption, which is what this answer rests on. Unproven: no `playRelease` APK traffic test. |
| Do you provide a way for users to request that their data be deleted? | **Yes, with caveats (see problems 1-2)** | In-app "Unpair Account" deletes local pairing, push state and the system account (`main/.../MainActivity.kt:1349-1360,1950-1962`, `main/.../security/SecurityWipe.kt:72-76`). The server copy is removed by the user on their own KyIdentity devices page (`TokenClient.kt:59` names it). Email route: privacy@busnes.app (from busnes.app/privacy.html). Unpair now revokes the device on the server and deletes the FCM token (problem 2). |
| Account creation | None in-app; accounts live on KyIdentity. Choose "My app does not allow users to create an account" | Enrollment only pairs an existing account (`MainActivity.kt:296-331`) |

## Data types

### Personal info > User IDs: **Collected**, not shared

- What: KyIdentity `userId` (`PairingClient.kt:95-97`) and `sub` in the sign-on assertion (`DeviceAssertion.kt:44`). Over FCM the developer's relay also receives it as `deviceUserId` in every push to a pairing made before FCM sealing that has not refreshed since (problem 5); sealed pushes do not carry it in the clear.
- Ephemeral: **No**. The server stores the device registration.
- Required. Pairing is the app's core function. Demo mode is the only path without it (`DemoMode.kt:10`).
- Purposes: **App functionality**, **Account management**.
- Not shared: the ID token handed to KyPost (`SignOnActivity.kt:146-155`) is a user-approved transfer, so it is exempt.

### Device or other IDs: **Collected**, not shared

- What:
  - Random installation UUID (`PairingStore.kt:23`).
  - `Build.MODEL` (`MainActivity.kt:365`).
  - Device public key and attestation chain (`PairingClient.kt:101,108`).
  - Push token or UnifiedPush endpoint (`PairingClient.kt:102-107`). The developer's FCM relay
    receives the FCM token with every push and keeps its SHA-256 hash, and KyIdentity's
    `deviceId` too for a keyless pairing (problem 5).
  - Firebase FID and FCM token (Firebase: "Generates and collects a per-installation identifier (FID)").
  - ML Kit per-installation ID.
- Ephemeral: **No**.
- Optional. Firebase mints the FID and token only when the user pairs or reconnects over FCM; UnifiedPush and demo users send none (problem 3).
- Purposes: **App functionality**. Add **Analytics** only if you count ML Kit's "diagnostics and usage analytics" and Firebase's user agent ("used internally by Google to determine platform and version adoption") as yours. Unproven which Play purpose Google expects. Conservative choice: App functionality + Analytics.
- Not shared: Google acts as a service provider. Firebase: it does not transfer data to third parties "except" subprocessors and "In accordance with your instructions"; ML Kit: "does not transfer this data to third-parties."

### App info and performance > Diagnostics: **Collected (conservative)**, not shared

- What: ML Kit latency, error codes, API configuration, device info (ML Kit disclosure); Firebase user agent.
- KyAuth integrates no crash reporting or analytics SDK. Its only dependencies are androidx, Material, biometric, the code scanner, firebase-messaging and the UnifiedPush connector (`app/build.gradle.kts:123-131`).
- Ephemeral: unproven. Google does not say.
- Optional. ML Kit data is sent only when the user scans; manual code entry avoids it (`MainActivity.kt:320-321`).
- Purposes: **Analytics** (Google's own use).

### App activity > Other actions: **Collected**, not shared

- What: MFA approve/deny and selected digits sent to KyIdentity (`MfaResponseClient.kt:28-34`).
- Ephemeral: unproven. It depends on KyIdentity's audit logging, so assume No.
- Optional. The user only answers requests they receive.
- Purposes: **App functionality**, **Fraud prevention, security, and compliance**.

### Not collected (state "No" or leave unselected)

| Type | Why | Evidence |
| --- | --- | --- |
| Location (precise/approximate) | No location permission or API | merged playDebug manifest: INTERNET, ACCESS_NETWORK_STATE, POST_NOTIFICATIONS, USE_BIOMETRIC, USE_FINGERPRINT, WAKE_LOCK, c2dm RECEIVE, DYNAMIC_RECEIVER_NOT_EXPORTED only (`app/build/intermediates/merged_manifests/playDebug/...`, a build artifact; release merge unproven) |
| Advertising ID | No `AD_ID` permission, no ads or analytics SDK | same manifest; `app/build.gradle.kts:123-131` |
| Photos/videos, camera | No CAMERA permission in play; the scanner runs in Play services and returns only the decoded string. ML Kit says nothing about sending frames; Google does not say either way, so unproven that none leave | `fdroid/AndroidManifest.xml:2-5` (CAMERA is fdroid-only), `gms/java/.../ChannelQrScanner.kt:6-11` |
| Biometrics | `BiometricPrompt` with a `CryptoObject`; the app sees only success or failure, never biometric data | `main/.../security/VaultUnlockPrompt.kt:19,37-57`, `MainActivity.kt:1651-1660` |
| Financial, health, messages, contacts, calendar, files, audio | None accessed | data_safety_scan: "record" hit is an idle timer (`MainActivity.kt:246`) |
| Installed apps | Only the calling app's signing-cert digest is checked locally, never sent | `main/.../signon/TrustedConsumers.kt:33-36,55-62` |
| TOTP secrets / vault | Local AES-GCM file; backup and device transfer excluded | `main/AndroidManifest.xml:12-14`, `main/res/xml/data_extraction_rules.xml` |
| Notifications content | Built locally from push data; `VISIBILITY_SECRET`; FCM payload is not developer-collected app data | `main/.../mfa/IncomingPush.kt:24-27,49,63` |

## Permissions / API hygiene

- No restricted or sensitive permissions in the play flavor. `INTERNET` and `POST_NOTIFICATIONS` are in `main/AndroidManifest.xml:3-4`; the rest are merged from firebase-messaging and androidx.biometric.
- `POST_NOTIFICATIONS` is requested at runtime only after pairing (`MainActivity.kt:1692-1695`), and posting checks the grant (`IncomingPush.kt:49`).
- Exported components:
  - The `AccountAuthenticator` service is gated by the system (`main/AndroidManifest.xml:36-46`).
  - `SignOnActivity` is exported, but every launch needs a live nonce (`main/AndroidManifest.xml:47-53`).
  - No Play declaration form applies.
- `<queries>` names three specific packages, not `QUERY_ALL_PACKAGES` (`main/AndroidManifest.xml:6-10`).
- App access: reviewers need the in-app "Try demo" path; declare restricted access with instructions (`MainActivity.kt:324-330`).

## Problems found

1. **Privacy policy does not cover KyAuth.** https://busnes.app/privacy.html (linked at `main/res/values/strings.xml:24`) never names KyAuth, Firebase Cloud Messaging, FIDs or KyIdentity pairing data. Play requires the policy to describe the app's data handling. Add a KyAuth section before submitting.
2. **Fixed: unpair revokes on the server.** It now sends a device-signed `POST .../devices/{id}/revoke` (KyIdentity `feat/device-self-revoke`) and deletes the FCM token and device key. If the server cannot confirm, the user is told to remove the phone on the devices page. Was: **Unpair is local-only.** `unpairIdentity()` (`MainActivity.kt:1950-1962`) and `SecurityWipe.wipe` (`security/SecurityWipe.kt:11-57`) never tell KyIdentity, so the device ID, model, public key and push token stay on the server. The deletion answer leans on the user removing the device on their KyIdentity devices page. Either revoke on the server during unpair (best effort), or tell the user in the unpair dialog.
3. **Fixed: Firebase starts only at pairing over FCM.** Auto-init is off in the manifest and switched on when the user pairs or reconnects over Firebase. The token is deleted on unpair, wipe, reset, and once KyIdentity confirms a switch to UnifiedPush. Unproven on a device: no traffic capture yet. Was: **Firebase collects before any consent or need.** FCM auto-init is on, so FID and device metadata go to Google at first launch: before pairing, in demo mode, and when the user has chosen UnifiedPush. Nothing calls `FirebaseMessaging.deleteToken()` (grep: no hits), whether the user unpairs, switches to UnifiedPush (`MainActivity.kt:1429-1432`) or wipes. Fix: set `firebase_messaging_auto_init_enabled=false` in `gms/AndroidManifest.xml`, enable it at pairing, and delete the token on unpair or transport switch. After that fix, Device IDs could arguably be marked Optional.
4. **The Firebase project looks like a scratch project (unproven).** `gms/res/values/firebase.xml:5-6` uses project `device-streaming-e3aa5b87`, which looks like an Android Studio Device Streaming project. Confirm it is the production project and that the committed API key (`firebase.xml:4`) is restricted to this package and signing cert.
5. **Keyless FCM pairings still carry IDs through the developer's relay and Google in clear.**
   Since FCM sealing, every pairing over FCM registers RFC 8291 keys (`main/.../pairing/PushKeys.kt`,
   `PushStore.newFcmKeys`), and KyIdentity then sends `data` = `{type, kyauth}` only, one
   fixed-size ciphertext (KyIdentity-server `internal/mfa/push_relay.go:225-236`). The app refuses
   plaintext challenges once KyIdentity holds its keys (`IncomingPush.fcmData`,
   `PushStore.acceptsPlaintextFcm`). A pairing made before that build has no keys until its next
   Reconnect (token rotation or transport switch) or a re-pair, and nothing forces one. Until then
   the relay (`workers/fcn`) and FCM see the FCM token and `data` = `type`, `title`, `body`,
   `challengeId`, `deviceId`, `deviceUserId`, `purpose`, `expiresAtEpochMs`, `devicePlatform`,
   never the username, which KyIdentity sends sealed only (`challengeData` vs `sealedChallenge`,
   `push_relay.go`; `workers/fcn/src/fcm.ts:253-260` forwards `data` as is). Sealed or
   not, the relay and FCM always see the FCM token, the send time and the message size. The relay
   keeps no raw token and no payload, only a claim named after the token's SHA-256 with the
   server's relay key id, which persists once a send has delivered (KyIdentity-server
   `push-relay-shared/relay-coordinator.ts:35-46,192-217`). Keep declaring User IDs and Device IDs
   as collected and not ephemeral: the form above covers keyless pairings and the FCM token, and
   sealing does not change what KyIdentity itself stores. Unproven on a device: no traffic capture
   of a sealed FCM push yet.

## Sources

- Play Data safety definitions: https://support.google.com/googleplay/android-developer/answer/10787469
- Firebase Play data disclosure (FCM, Installations): https://firebase.google.com/docs/android/play-data-disclosure
- ML Kit / Google code scanner data disclosure: https://developers.google.com/ml-kit/android-data-disclosure
- Account deletion policy: https://support.google.com/googleplay/android-developer/answer/13327111
- App access (reviewer credentials): https://support.google.com/googleplay/android-developer/answer/15748846
- Busnes privacy policy: https://busnes.app/privacy.html
