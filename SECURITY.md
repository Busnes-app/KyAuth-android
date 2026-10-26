# Security Policy

## Reporting a vulnerability

Report vulnerabilities in KyAuth privately through
[GitHub Security Advisories](https://github.com/Busnes-app/KyAuth-android/security/advisories/new),
not a public issue. Include the affected version, what an attacker can do, and steps to
reproduce. Do not disclose publicly until a fix is released.

We acknowledge reports within 2 business days, then agree a severity and timeline with you,
ship the fix, and credit you in the release notes unless you prefer otherwise.

## Scope

TOTP imports, replacement secrets and generation enforce a 128-bit minimum decoded
secret. Legacy weak records remain readable and editable, with code generation and
copying refused until the account provider supplies a new setup. The app never
repairs a secret by padding/hashing it or silently removes an entry; see the
[local TOTP guidance](README.md#install-and-use-independently).

KyAuth's security contract is [AGENTS.md](AGENTS.md): the vault, the device key, Push MFA,
passkeys and sign-on. A way to break any promise there is in scope. Server-side issues belong
to [KyIdentity-server](https://github.com/Busnes-app/KyIdentity-server/security/advisories/new).

## See also

- [docs/VERIFYING-RELEASES.md](docs/VERIFYING-RELEASES.md): verify a release APK and rebuild it
- [docs/ASSURANCE-CASE.md](docs/ASSURANCE-CASE.md): threat model and the argument that the protections hold
