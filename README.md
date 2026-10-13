# KyAuth for Android

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
- A KyIdentity server reachable over HTTPS.

## Builds

| Build | Channel | Sign-in request delivery | QR scanner |
|---|---|---|---|
| `play` | Google Play | Firebase (default) or UnifiedPush | Google Play services |
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

Any JDK 17 or newer can start the build. The Gradle wrapper fetches Gradle, and Gradle provisions
the JDK 25 its daemon needs.

```bash
./gradlew assemblePlayDebug          # or assembleGithubDebug, assembleFdroidDebug
./gradlew testPlayDebugUnitTest testFdroidDebugUnitTest lintPlayDebug lintFdroidDebug
./gradlew connectedPlayDebugAndroidTest   # needs an emulator with a screen-lock PIN
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

## Contributing and security

- [CONTRIBUTING.md](CONTRIBUTING.md) covers setup and the rules a change must keep.
- [AGENTS.md](AGENTS.md) is the product and security contract. Read it before you change
  behaviour.
- Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in a public
  issue.

## License

[MIT](LICENSE.txt)
