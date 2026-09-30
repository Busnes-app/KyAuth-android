# Attestation-gated MFA grade for device sign-on

Date: 2026-09-30
Status: draft, awaiting review
Builds on: `2026-09-29-kyidentity-account-manager-signon-design.md` (device sign-on grant, shipped as KyIdentity #66/#67, KyAuth #14/#15, kypost-server #240/#243, KyPost #132)

## Problem

The device sign-on grant is single-factor. The security audit on KyIdentity #66 (P1) was right: KyIdentity
enrols any P-256 public key and cannot tell a hardware-backed, biometric-gated key from a key held in
software, so claiming MFA from one signature was unfounded. The fix shipped was to stamp primary evidence
only, which means every account with mandatory MFA (all of them, in this suite) refuses device sign-on.
The feature is built but dormant.

Android Key Attestation is the evidence the server was missing: a certificate chain, rooted at Google's
hardware attestation roots, signed inside the TEE or StrongBox, stating where the key lives and that it can
only be used after a per-use user authentication.

## Decision

At pairing, KyAuth generates a fresh device key with a server-derivable attestation challenge and uploads
the attestation chain. KyIdentity verifies the chain and records an attested level per device: `none`,
`tee` or `strongbox`. Only an attested device earns MFA grade in the sign-on grant: hardware possession
plus hardware-enforced per-use user verification count as two factors. Unattested devices keep today's
single-factor behaviour. Pairing never fails because of attestation; only the grade does.

Chosen bar: TEE or StrongBox. A locked bootloader is an operator setting, off by default.

### Rejected alternatives

**Play Integrity.** Needs Google Play services on the phone and a Google Cloud project on the server; wrong
fit for a self-hosted suite, and it attests the app, not the key.

**Trusting the client's own `KeyInfo.securityLevel` check.** KyAuth already does this for its KyIdentity
passkey, but it is a claim the server cannot verify. The audit refused exactly that.

**Google's Kotlin verifier library on the server.** KyIdentity is Go; the verification is stdlib X.509 plus
one ASN.1 structure and does not justify a JVM.

## Design

### 1. KyAuth: an attested key per pairing

The attestation challenge is fixed when the key is generated, so the key must be created for this pairing:

- On pairing confirmation, before `PairingClient.register`, KyAuth deletes the `kysignon-device-signing-v1`
  alias and generates a new key: same parameters as today (P-256, SHA-256, `setUserAuthenticationRequired
  (true)`, per-use auth with biometric or device credential), plus `setAttestationChallenge(challenge)`,
  `setIsStrongBoxBacked(true)` first and a TEE retry on `StrongBoxUnavailableException`.
- `challenge = SHA-256("kyidentity-attest-v1|" + credential)` where `credential` is the pairing token on
  the QR or deep-link path, or `userId + "|" + pinCode` on the manual path. Thirty-two bytes, within the
  128-byte limit. The server recomputes it from the same request fields, so no extra round trip and nothing
  new on the QR.
- The registration request gains `attestation`: a JSON array of base64 DER certificates, leaf first, from
  `KeyStore.getCertificateChain(alias)`. If generation with a challenge throws, KyAuth generates without a
  challenge and omits the field; if `getCertificateChain` returns a single self-signed certificate, it is
  sent as is and the server grades it `none`.
- The registration response's `device.attestedLevel` is stored in `PairedAccount` beside `canSignOn`.
  Settings shows "Attested: StrongBox / TEE" or "Not attested. Pair again to attest this phone." The
  system account is unaffected.
- Consequences: re-pairing rotates the device key (the server upsert already replaces `public_key`; push
  MFA responses signed with the old key stop working, which is correct for a new pairing). Existing
  pairings stay `none` until re-paired. `SecurityWipe` behaviour is unchanged.

### 2. KyIdentity: the verifier

New package `internal/attest` with one entry point:

```
Verify(chain [][]byte, want Expectation) Result
Expectation{Challenge []byte; PublicKey SPKI DER; AppPackage string; AppDigests []string;
            RequireLockedBootloader bool}
Result{Level none|tee|strongbox; Reason string; BootState string; Serials []string}
```

Checks, in this order; the first failure sets `Level = none` with `Reason` and stops:

1. Every certificate parses; each signs the next; the last is one of the trusted roots. Trusted roots are
   Google's hardware attestation roots embedded at build time, refreshed daily from
   `https://android.googleapis.com/attestation/root`, plus an operator PEM file. Chains under the
   long-standing RSA root (`SERIALNUMBER=f92009e853b6b045`) are accepted past their expiry, as Google
   documents for pre-2021 factory keys; every other certificate must be within its validity.
2. No certificate serial appears in Google's status list (`REVOKED` or `SUSPENDED`), read from a cache
   that honours the endpoint's `Cache-Control` (24 hours today). No cache and no fetch means `none`.
3. Walking from the root, the first certificate carrying OID `1.3.6.1.4.1.11129.2.1.17` is the attestation
   certificate; any later certificate carrying it rejects the chain.
4. That certificate's public key equals the registered SPKI.
5. `KeyDescription`: `attestationSecurityLevel` and `keyMintSecurityLevel` are both TEE (1) or StrongBox (2)
   and equal; `attestationChallenge` equals the expectation.
6. `hardwareEnforced`: `purpose` contains SIGN (2); `algorithm` is EC (3); `ecCurve` is P-256 (1);
   `origin` is GENERATED (0); `userAuthType` present and non-zero; `authTimeout` absent; `noAuthRequired`
   absent. `rootOfTrust` is decoded and recorded (`deviceLocked`, `verifiedBootState`).
7. `softwareEnforced.attestationApplicationId` contains package `org.kysecurity.authenticator` and at least
   one signature digest from the pinned set.
8. If `RequireLockedBootloader`: `deviceLocked` true and `verifiedBootState` is `Verified` or `SelfSigned`
   (a locked bootloader running an owner-signed OS such as GrapheneOS). `Unverified` and `Failed` yield
   `none`.

`Level` is `strongbox` when both security levels are StrongBox, else `tee`. The verifier is pure apart
from the two caches, which are injected so tests never touch the network.

### 3. Registration and storage

- `RegisterNativeDevice` computes the expected challenge from the request's credential, calls `Verify` when
  `attestation` is present, and stores on `native_devices`: `attested_level TEXT NOT NULL DEFAULT 'none'`,
  `attested_at DATETIME`, `boot_state TEXT` (`locked-verified`, `locked-selfsigned`, `unlocked`, `unknown`),
  `attestation_serials TEXT` (JSON array). Existing rows migrate to `none`.
- The registration audit row carries `attestedLevel`, `bootState` and `reason`.
- The request body is capped (64 KiB) because chains can be several kilobytes.
- The registration response's `device` includes `attestedLevel` and `bootState`.

### 3b. Locked-bootloader setting

- An admin setting on the sign-on section of the KyIdentity web UI, `attestation.requireLockedBootloader`,
  default off, stored in the existing settings store and read on every registration and by the sweep.
- Off: boot state is recorded and shown, not enforced. On: check 8 applies to new pairings, and the daily
  sweep downgrades already-attested devices whose stored boot state fails it.
- Enforcement is at pairing and at the sweep, not per request: unlocking a bootloader later wipes the
  hardware key on most devices, so the next sign-on fails and a re-pair records the new state.

### 4. The grant

In `ExchangeDeviceAssertion`, after the existing eligibility checks:

- `attested_level == none`: unchanged. Primary evidence only, `amr: ["pop"]`, `acr: urn:kysignon:acr:device`,
  reuse-mode password policies only; MFA-required accounts are refused with `signon_not_permitted`.
- `attested_level in {tee, strongbox}`: evidence carries `PrimaryAuthenticatedAt` and
  `FactorAuthenticatedAt` = now with `FactorMethod: "push"` (the enrolled push-approver factor, bit 2, is
  this same key). The enrollment view and `RecordIssuedToken` then admit MFA-required accounts; app
  policies of every mode are evaluated as for the code grant, since every use is a fresh hardware-gated
  authentication. ID token: `amr: ["hwk","user","mfa"]`, `acr: urn:kysignon:acr:mfa`, plus
  `attested: "tee"|"strongbox"`. The atomic device binding in `RecordIssuedToken` gains `attested_level`,
  so a downgrade landing mid-exchange refuses.

### 5. Revocation sweep

A daily job (piggybacking on the existing cleanup ticker) refreshes the roots and status caches, then for
every device with `attested_level != none` checks its stored serials against the status list and the
locked-bootloader setting against its stored boot state; failures set `attested_level = none` with an
audit row `device.attestation_downgraded`. The user sees "Not attested" and re-pairs.

### 6. Surfaces

- KyIdentity devices page: badge `Attested: StrongBox`, `Attested: TEE`, or `Not attested`, with the boot
  state as a secondary line; a hint to re-pair when unattested. Admin sign-on settings gain the
  locked-bootloader switch with one sentence of help text.
- KyAuth Settings: the same badge and hint.
- Consumer apps: no change. A consumer that wants MFA grade only sees the token's `amr`.

### 7. Configuration

Environment (deployment facts): `KYIDENTITY_ATTESTATION_EXTRA_ROOTS` (PEM file path, optional),
`KYIDENTITY_ATTESTATION_STATUS_URL` (default Google's; empty disables the revocation check and logs a
warning at startup), `KYIDENTITY_KYAUTH_CERT_SHA256` (comma-separated digests; default the Play digest
`52f61684029401fcb0137b334ad41907f83948fa1ec1377834f3b4291765fd7b`). The web app is not involved.

Admin setting (policy): `attestation.requireLockedBootloader` (section 3b).

### 8. Testing

- `internal/attest`: a test CA (root, intermediate, attestation certificate) built in-process with the
  extension encoded by hand via `encoding/asn1`; the root pool and status list are injected. One test per
  check in section 2, including: extension on an intermediate with a second on the leaf; software level;
  challenge mismatch; `authTimeout` present; `noAuthRequired` present; wrong package; wrong digest;
  revoked intermediate; expired factory chain under the RSA root accepted; expired chain under another
  root refused; unlocked bootloader with the setting on and off.
- Registration and grant tests: attested device admits an MFA-required user with `amr` containing `mfa`;
  unattested device keeps every existing refusal; downgrade between validation and insert refuses.
- KyAuth: unit test for the challenge derivation (both credential shapes); instrumented test that
  generation with a challenge on the emulator produces a chain the server grades `none` (software level),
  which is the honest emulator result.
- Physical device: capture the real chain from your phone into a golden fixture once, and add it as the
  positive test against Google's real roots. Until then the positive path is unproven, and AGENTS.md says
  so.

### Security properties

| Property | How | Proof |
|---|---|---|
| MFA grade only for hardware keys | Chain to Google's root; levels TEE/StrongBox in the extension | Section 2 checks 1, 5; tests |
| Only per-use user verification counts | `userAuthType` present, `authTimeout` absent, from the hardware-enforced list | Check 6; tests |
| The attested key is the registered key | Extension certificate's public key equals the SPKI | Check 4; test |
| The key was generated for this pairing | Challenge derived from the pairing credential | Check 5; test |
| The key belongs to KyAuth | Application id package + signing digest | Check 7; test |
| Revoked provisioning is caught | Status list at pairing and daily | Checks 2, 5; tests |
| Pairing keeps working everywhere | Every failure grades `none` | Registration test |

### Known gaps carried, not fixed here

- Grade is decided at pairing and by a daily sweep, not per request.
- `softwareEnforced` fields (the application id) are trusted only while the OS is not compromised; the
  hardware-enforced fields do not depend on that.
- The emulator cannot produce a passing chain, so the positive path needs a phone.
- Vendor roots other than Google's are admitted only through the operator PEM file.

## Sequence and repos

1. KyIdentity-server: schema, `internal/attest`, registration wiring, grant change, sweep, setting, UI,
   docs, tests.
2. kyauth-android: challenge derivation, key regeneration with attestation, chain upload, Settings badge,
   docs, tests.
3. Physical-phone verification and the golden fixture.

Consumers need no change.
