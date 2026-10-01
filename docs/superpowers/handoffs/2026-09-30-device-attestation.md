# Hand-off: attestation-gated MFA grade for device sign-on (2026-09-30)

**Repo:** KyIdentity-server, kyauth-android
**PRs:** KyIdentity #68 https://github.com/Busnes-app/KyIdentity-server/pull/68 (merge first); KyAuth #16 https://github.com/Busnes-app/KyAuth-android/pull/16
**Worktrees:** KyIdentity-server/.claude/worktrees/attestation (feature/device-attestation, 86c5506); kyauth-android/.claude/worktrees/attestation (feature/device-attestation, 662f40f)
**Spec / plans:** docs/superpowers/specs/2026-09-30-device-signon-attestation-design.md, docs/superpowers/plans/2026-09-30-attestation-{1,2}-*.md (branch design/kyidentity-account-manager-signon)
**Ledgers (rulings, deferred minors):** .superpowers/sdd/2026-09-30-attestation-{1-kyidentity-server,2-kyauth-android}/progress.md (git-ignored, this checkout)

## Done
- KyIdentity: `internal/attest` verifier (Google roots embedded + daily refresh, status list with staleness, 8 ordered checks, 33-case refusal table), registration grades before enrolment and persists the grade in the same upsert as the key, grant gives attested devices `amr [hwk,user,mfa]` / `acr mfa` / `attested` claim, admin setting `attestation.requireLockedBootloader`, daily sweep, devices badge, docs. CI green (15 packages -race, vitest 165).
- KyAuth: per-pairing key regeneration with challenge, StrongBox→TEE→plain fallback, chain upload, level/boot state stored and shown, failed re-pair clears the dead pairing (keeps the login passkey). Unit/lint/build green; instrumented key test 3/3 on emulator Pixel_10.

## Left
- Merge #68, then #16. Pair a physical phone against a KyIdentity running #68; confirm Settings shows Attested: TEE/StrongBox and the KyIdentity devices page shows the badge. Capture the real chain as a golden fixture for `internal/attest` (spec phase 3). Try a failed re-pair on a paired phone (expired QR) and confirm the app returns to the pairing screen.
- Decisions for Yoshi: (1) staging-alias key rotation (generate into a second alias, switch on success) instead of clearing the pairing on a failed re-pair; (2) the spec copy "Pair again to attest this phone." also shows on phones that can never attest (emulators, older servers, unpinned signing digests).

## Careful
- Emulators ship software KeyMint and always grade `none`; never claim the positive path works without the phone.
- The KyAuth instrumented test deletes the production Keystore alias: run it on an unpaired device only.
- A KyAuth re-pair rotates the device key; push MFA signed with the old key stops working, by design.
- Emulator emulator-5554 (Pixel_10, PIN 1234) was left running on the desktop.
