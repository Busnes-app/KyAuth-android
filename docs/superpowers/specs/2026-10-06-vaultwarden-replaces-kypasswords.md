# Vaultwarden replaces KyPasswords

Decided 2026-10-06. Status: implemented.

## Decision

The suite replaces KyPasswords with Vaultwarden. KyAuth does not become a Bitwarden client
(option B). Android users manage passwords and passkeys with the official Bitwarden app
pointed at Vaultwarden.

KyAuth has no Vaultwarden integration of any kind: no client, sign-in, import, export or link.
Passwords and passkeys are entirely the Bitwarden app's job.

KyAuth becomes authenticator-only: TOTP, Push MFA, KyIdentity sign-on and the KyIdentity
login passkey. It keeps no password or passkey vault, synced or device-only.

## Why

- Vaultwarden speaks the Bitwarden protocol: per-cipher EncStrings, a master key derived from
  master password and email, an account key, org keys, `/api/sync`. None of KyAuth's
  whole-file KDBX sync, envelope crypto or pairing carries over; a client is a rewrite.
- The Bitwarden Android app is open source (GPL-3.0), works with Vaultwarden, and is already
  an Autofill service and Credential Manager passkey provider.
- Holding the Bitwarden account key would give KyAuth every item in the account, including
  shared organisation collections. Not holding it is the smaller attack surface.
- A device-only vault beside Bitwarden is a second password manager competing in the system
  picker. Dropping it also removes the Autofill service from the first Play review.

## Removed

- `passwords/kypasswords/`: client, pairing parser, envelope crypto, vault sync, store, tests
  and `tools/gen_argon2id_envelope_fixture.py`. BouncyCastle goes with the envelope crypto,
  its only user.
- The password vault: `passwords_vault.kdbx`, `KdbxPasswordVault`, entries, generator,
  `DomainMatcher`, `TrustedBrowsers`, Recycle Bin, reused-password report, conflict copies,
  `OfflineVaultKey`, and the KDBX preservation tooling (`tools/vault_preservation.js`,
  `KdbxPreservationTest`, the Node and Python Verification steps).
- `KyAuthAutofillService`, `AutofillParser`, `AutofillUnlockActivity` and the Autofill
  manifest entry.
- Vault passkeys and passwords in the Credential Provider: the vault paths of
  `CredentialAuthActivity` and `CredentialEntryBuilder`, `CredentialUnlockActivity`, and
  passkey QR (hybrid) scanning.
- The Passwords and Push MFA tabs. See UI below.
- `VaultKek` wraps one key, the TOTP vault key, instead of two.
- The KyPasswords and password-vault bullets in `AGENTS.md`, and the outstanding-work items
  they carry: non-Play browsers, vault size ceilings, exportable vault passkeys, credential
  picker accumulation.

## Kept

- TOTP vault, Push MFA, app lock and PIN, local wipe.
- KyIdentity pairing with device-key attestation, and AccountManager sign-on (`signon/`).
- The KyIdentity login passkey and what it needs: `KyAuthCredentialProviderService` (offering
  only that entry), `WebAuthnEngine`, `ClientData`, `RpId` with `PublicSuffix`,
  `DigitalAssetLinks`, `IdentityPasskey*`.

## TOTP backup

None, decided 2026-10-06. Losing the phone loses its TOTP entries; there is no backup, export
or sync to add.

## UI

- The TOTP Vault tab is renamed **Vault**. A pending Push MFA request shows at the top of
  Vault, above the TOTP list; with none pending, nothing is shown there.
- The bottom pill becomes Vault, lock shield, Settings.
- A push notification opens Vault (`loadPendingPushChallenge` selects it instead of the MFA
  tab). An expired request clears itself as it does today.

## Migration

None. KyAuth has no public build and has not passed Play review, so no installed user holds a
`passwords_vault.kdbx`. Code is removed directly, with no export release first.

## Open questions

- KyVault-server's retirement and its KyRecovery deposits (outside this repo).
- Whether Vaultwarden sign-in can go through KyIdentity SSO (unverified; the master password
  would still decrypt the vault).
