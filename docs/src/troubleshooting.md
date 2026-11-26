# Troubleshooting

- **App refuses to run:** confirm Android 12+ and a secure screen lock.
- **F-Droid has no push:** install or select a UnifiedPush distributor and check its connectivity.
- **Private distributor refused:** the KyIdentity operator must evaluate the explicit private-callback opt-in.
- **Pairing expires:** issue a fresh code and complete the flow within 90 seconds.
- **TOTP rejected:** check system time and setup parameters before replacing the entry.
- **Changing channels:** the signatures differ, so an in-place update will not work. Recover TOTP access before uninstalling.

When reporting a problem, include the product version, platform, failed task and a redacted error. Exclude pairing links, device secrets, recovery codes, custodian shares and private content.
