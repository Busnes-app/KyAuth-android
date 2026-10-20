# Contributing to KyAuth

Read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before you contribute.

## Setup

Use the Android SDK required by the build and JDK 17+ to start the wrapper. Gradle provisions its configured JDK 25 daemon toolchain; an offline build needs those artifacts already cached.

Run the test suite and build the debug APK before you submit a change:

```bash
./gradlew testPlayDebugUnitTest testFdroidDebugUnitTest lintPlayDebug lintFdroidDebug
./gradlew assemblePlayDebug assembleFdroidDebug
```

## Security rules

- Keep release pairing HTTPS-only.
- Do not weaken QR expiry, origin validation, or redirect blocking.
- Do not log secrets, PINs, pairing credentials, vault keys, OTPs, or passwords.
- Keep sensitive data in app-private storage.
- Preserve the background lock, clipboard clearing, screenshot protection, and wipe behavior.
- Document a new secret, network path, storage location, or security trade-off before review.

## Product rules

- Use `KyAuth` in user-visible text.
- KyAuth stores no passwords and no passkeys; those belong to the Bitwarden app.
- Keep the 15 suite themes numerically aligned with the source palette in `ThemeManager.kt`.

## Documentation

Read [AGENTS.md](AGENTS.md) before you edit the project. Update it when a durable contract or project boundary changes.

Update relevant Markdown files when a user-visible behavior, license, or contributor workflow changes.

## Pull requests

- Make one logical change per pull request.
- Explain the user effect and security effect.
- Add or update tests for non-trivial behavior.
- State which checks you ran.
- Add AI attribution when an AI tool materially contributed.

## License

KyAuth uses the MIT License. By contributing, you license your contribution under MIT.
