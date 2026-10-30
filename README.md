# KyAuth for Android

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15921/badge)](https://www.bestpractices.dev/projects/15921)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Busnes-app/KyAuth-android/badge)](https://scorecard.dev/viewer/?uri=github.com/Busnes-app/KyAuth-android)

KyAuth is the Android authenticator for the KySecurity suite. It pairs a
phone with your self-hosted [KyIdentity](https://github.com/Busnes-app/KyIdentity-server) server
and gives you:

- **Push MFA.** Approve or deny a KyIdentity sign-in with number matching and one fingerprint.
  It works while KyAuth is locked, without opening the vault.
- **TOTP codes.** Scan a QR or add accounts by hand. Codes are encrypted on the device, behind a
  biometric (and optional PIN) lock.
- **App sign-on.** Suite apps such as KyPost sign in through KyAuth's Android account, with one
  biometric per sign-in and no password typed.

KyAuth is not a password manager. Passwords and passkeys for other sites belong in the
[Bitwarden](https://bitwarden.com/) app, pointed at your Vaultwarden.

## Requirements

- Android 12 (API 31) or newer.
- A secure screen lock (PIN, pattern or password). The vault key is bound to it; KyAuth will not
  run without one.
- For push MFA and app sign-on: a KyIdentity server reachable over HTTPS. Local TOTP code generation works without KyIdentity.

## Install and use independently

Install KyAuth from [Google Play](https://play.google.com/store/apps/details?id=org.kysecurity.authenticator),
or a signed APK from a published [GitHub release](https://github.com/Busnes-app/KyAuth-android/releases).
For a GitHub APK, check the release’s certificate digest and SHA-256 provenance. KyAuth is not
on F-Droid yet, although the repository has an F-Droid build. Keep the same channel/signer for updates.

To use local TOTP, set a secure device lock, open **Vault**, scan the site’s authenticator
QR or enter its setup key, and confirm a generated code at that site. Pairing KyIdentity is
not required for this path. Save that site’s recovery codes separately: KyAuth has no
backup, export or sync.

Setup keys must contain at least 128 bits (16 bytes after Base32 decoding), as
required by RFC 4226. A short key is refused when scanned, added or substituted.
An older entry with a short key stays in the vault with its name, website, notes
and original secret, but shows **Unavailable** and instructions to set up two-step
verification again with the account provider. Long-press it to edit its details;
unchanged legacy secrets can be retained while you arrange a replacement.
Use the provider's recovery/sign-in process to get a new authenticator setup and
confirm its code there. Do not pad, extend or otherwise change a secret on your
own: it must match the provider. No records are automatically deleted or migrated.

For push/sign-on, first install [KyIdentity](https://github.com/Busnes-app/KyIdentity-server),
then follow [Getting started](#getting-started). Configure FCM/APNs relay or UnifiedPush
on the server as appropriate and observe a real browser sign-in request and approval.
Unit tests and pairing success alone do not prove background delivery.

## Builds

| Build | Channel | Sign-in request delivery | QR scanner |
|---|---|---|---|
| `play` | [Google Play](https://play.google.com/store/apps/details?id=org.kysecurity.authenticator) | Firebase (default) or UnifiedPush | Google Play services |
| `github` | GitHub releases | Firebase (default) or UnifiedPush | Google Play services |
| `fdroid` | F-Droid | UnifiedPush only, no Google code | Built-in (zxing) |

All three share one app ID, so only one can be installed at a time. They are signed with
different keys: switching builds means uninstalling, then pairing again.

### UnifiedPush

With UnifiedPush, KyIdentity sends sign-in requests straight to your own distributor, such as
[ntfy](https://ntfy.sh), with no Google relay in between. Requests are end-to-end encrypted
(RFC 8291): the distributor sees when a request is sent, never what it says.

On F-Droid, install a distributor before pairing; KyAuth asks you to pick one when it opens.
On Play and GitHub builds, switch in **Settings → Sign-in request delivery**.

A distributor on your LAN (a private IP) needs `KYIDENTITY_ALLOW_PRIVATE_CALLBACKS=true` on the
KyIdentity server. It is off by default.

## Getting started

1. In KyIdentity, start pairing a new device to get a pairing QR code.
2. In KyAuth, tap **Scan QR Code** and scan it within 90 seconds, or enter the server URL and
   pairing token by hand.
3. Confirm with your fingerprint. KyAuth now receives your sign-in requests.

## What to know before you rely on it

- **No backup, export or sync, by design.** Your TOTP entries live only on this phone. If you
  lose it, you lose them. Recover KyIdentity access with your recovery codes or an admin MFA
  reset, and keep each site's own recovery codes.
- **It locks itself.** KyAuth locks when it leaves the screen and after idle time (5 minutes by
  default, set in Settings). A copied code clears from the clipboard when it expires.
- **Five wrong PINs wipe it.** After the fifth failed PIN, KyAuth erases its local data and keys.
- **Release builds** block screenshots, disable Android backup, and refuse plain HTTP.

## Building

Clone this repository, install the Android SDK required by `app/build.gradle.kts`, and
set `ANDROID_HOME` or a gitignored `local.properties` SDK path. For a local evaluation,
`./gradlew installFdroidDebug` builds/installs a development APK on a connected Android
12+ test device without Firebase. It cannot update a differently signed release.

Any JDK 17 or newer can start the build. The Gradle wrapper fetches Gradle, and Gradle provisions
the JDK 25 its daemon needs.

```bash
./gradlew assemblePlayDebug          # or assembleGithubDebug, assembleFdroidDebug
./gradlew testPlayDebugUnitTest testFdroidDebugUnitTest lintPlayDebug lintFdroidDebug
./gradlew connectedPlayDebugAndroidTest   # needs an emulator; Keystore tests temporarily set a screen-lock PIN
# A physical-device check is still needed for real push, biometrics and hardware attestation.
```

Release builds are signed only when signing material is present, either as `KYAUTH_KEYSTORE`,
`KYAUTH_STORE_PASSWORD`, `KYAUTH_KEY_ALIAS` and `KYAUTH_KEY_PASSWORD` environment variables or in
a git-ignored `keystore.properties` (`storeFile`, `storePassword`, `keyAlias`, `keyPassword`).
Without them, `assemble*Release` produces an unsigned APK.

## Releasing

Bump `versionCode` and `versionName`, add `fastlane/metadata/android/en-US/changelogs/<versionCode>.txt`,
then push a `v<versionName>` tag. The Release workflow signs the GitHub and F-Droid APKs and
publishes them with SHA-256 sums, build provenance and the signing certificate digest. It reads
the `release` environment's secrets: `KYAUTH_KEYSTORE_BASE64` (`base64 -w0` of the keystore),
`KYAUTH_STORE_PASSWORD`, `KYAUTH_KEY_ALIAS` and `KYAUTH_KEY_PASSWORD`. F-Droid notes are in
[docs/f-droid.md](docs/f-droid.md).

The same run builds the Play bundle, signed with that keystore as the Play upload key, and a
second `play` job uploads it to the internal track with `PLAY_SERVICE_ACCOUNT_JSON` (a service
account with Release permission on this app). Promote it to testing or production in Play Console.
Without that secret the job skips the upload with a warning; upload the run's `play-bundle`
artifact by hand.

Google Play re-signs what it installs. KyIdentity servers grade attestation against
`KYIDENTITY_KYAUTH_CERT_SHA256`, so it must list the Play app signing certificate's SHA-256
(Play Console, Test and release → App integrity → App signing) as well as the GitHub release
digest, lowercase hex without colons.

## Contributing and security

- [CONTRIBUTING.md](CONTRIBUTING.md) covers setup and the rules a change must keep.
- [AGENTS.md](AGENTS.md) is the product and security contract. Read it before you change
  behaviour.
- Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in a public
  issue.
- [Verifying releases](docs/VERIFYING-RELEASES.md) checks an APK's signing certificate and build
  provenance, and rebuilds it from source to compare.
- [Assurance case](docs/ASSURANCE-CASE.md) covers the threat model, the trust boundaries and why the
  security requirements hold.

## License

[MIT](LICENSE.txt)

[![OctoCounts](https://api.octocounts.com/badge/Busnes-app/KyAuth-android/branch/main)](https://octocounts.com/github/Busnes-app/KyAuth-android/tree/main)

## Documentation

- [Verifying releases](docs/VERIFYING-RELEASES.md) — check a release APK's signature and source.
- [F-Droid](docs/f-droid.md) — how the F-Droid listing is produced.
- [TLS key-floor evidence](docs/native-tls-evidence.md) — the investigation behind Android's certificate-key minimums.
- [Assurance case](docs/ASSURANCE-CASE.md) — threat model, trust boundaries, and why the security requirements are met.
- [Contributing](CONTRIBUTING.md) — how to propose a change and what it must pass.
- [Security policy](SECURITY.md) — how to report a vulnerability privately.
