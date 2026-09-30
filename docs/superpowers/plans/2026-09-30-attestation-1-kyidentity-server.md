# KyIdentity attestation verifier Implementation Plan (1 of 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** KyIdentity verifies an Android key attestation chain at native-device registration, records an attested level per device, and grants MFA grade to device sign-on only for attested devices.

**Architecture:** A pure `internal/attest` package (ASN.1 `KeyDescription` decoder, chain walk to trusted roots, status-list check, policy checks) with injected root and status caches; registration computes the expected challenge from the pairing credential and stores the result on `native_devices`; the device grant reads `attested_level` to decide evidence and claims; an admin setting gates on a locked bootloader; a daily sweep re-checks revocation and the setting.

**Tech Stack:** Go stdlib (`crypto/x509`, `encoding/asn1`, `net/http`), `modernc.org/sqlite`, existing settings/audit patterns; React web app.

**Spec:** `docs/superpowers/specs/2026-09-30-device-signon-attestation-design.md`.

**Repo:** `/home/yoshi/git/busnes.app/KyIdentity-server`, branch `feature/device-attestation` from `master` (PR #67 must be merged first; if not, branch from `feature/device-signon-origin`).

## Global Constraints

- Expected challenge = SHA-256 of `"kyidentity-attest-v1|" + credential`, credential = `pairingToken` when present else `userId + "|" + pinCode`. Byte-identical to KyAuth.
- Attestation extension OID `1.3.6.1.4.1.11129.2.1.17`. Take the first certificate bearing it walking from the root; any later occurrence rejects.
- Levels: `none`, `tee`, `strongbox`. `attestationSecurityLevel` and `keyMintSecurityLevel` must both be 1 (TEE) or 2 (StrongBox) and equal.
- `hardwareEnforced`: purpose ⊇ 2 (SIGN), algorithm 3 (EC), ecCurve 1 (P-256), origin 0 (GENERATED), `userAuthType` present and non-zero, `authTimeout` (505) absent, `noAuthRequired` (503) absent. `rootOfTrust` (704) decoded when present.
- `softwareEnforced.attestationApplicationId` (709) must name package `org.kysecurity.authenticator` and a signature digest in the pinned set (default `52f61684029401fcb0137b334ad41907f83948fa1ec1377834f3b4291765fd7b`).
- Trusted roots: embedded JSON from `https://android.googleapis.com/attestation/root`, refreshed daily; plus `KYIDENTITY_ATTESTATION_EXTRA_ROOTS` PEM file. Chains under the root with subject `SERIALNUMBER=f92009e853b6b045` are accepted past expiry; all other certificates must be within validity at verification time.
- Status list `KYIDENTITY_ATTESTATION_STATUS_URL` (default `https://android.googleapis.com/attestation/status`), cached honouring `Cache-Control: max-age`; a serial in `entries` with status `REVOKED` or `SUSPENDED` grades `none`. No usable cache → `none`. Empty URL disables the check with a startup warning.
- Every verification failure grades `none` with a reason; registration never fails because of attestation.
- Registration body cap 64 KiB.
- Boot state strings: `locked-verified`, `locked-selfsigned`, `unlocked`, `unknown`.
- Grant: attested devices get `FactorAuthenticatedAt = now`, `FactorMethod: "push"`, all policy modes evaluated as the code grant does, `amr: ["hwk","user","mfa"]`, `acr: urn:kysignon:acr:mfa`, claim `attested`; `none` keeps today's behaviour exactly. `DeviceBinding` gains `AttestedLevel` checked in the INSERT.
- Admin setting key `attestation` in `system_settings`, JSON `{"requireLockedBootloader": bool}`, default false; `GET/PUT /api/admin/attestation/settings` (PUT step-up gated like alerts).
- CI: `gofmt -l .`, `go vet ./...`, `go test -race -count=1 -timeout 20m ./...`, `cd web && npm run build && npm test`.

## Review Focus

1. A chain whose root is trusted but whose intermediate is expired (pre-2021 factory key) must still grade when the root is the legacy RSA root, and must grade `none` under any other root. Pinned in Task 3.
2. A `KeyDescription` where `attestationChallenge` matches but `userAuthType` is present in `softwareEnforced` only (not hardware) must grade `none`. Pinned in Task 2.
3. `userAuthType = 0xFFFFFFFF` (ANY) must decode without overflow and count as present. Pinned in Task 2.
4. A registration with `attestation` present but the token path's raw token differing in case or whitespace from what was generated: the challenge is computed from the request bytes exactly as received, so it mismatches and grades `none`; the pairing still succeeds. Pinned in Task 4.
5. A device downgraded by the sweep mid-exchange must be refused by the atomic binding. Pinned in Task 5.

---

### Task 1: Schema and model

**Files:**
- Modify: `internal/store/store.go` (DDL ~128-143; migrations chain; `RegisterNativeDeviceWithPairingToken` insert ~1371; `UpsertNativeDevice`; `ListUserNativeDevices` ~1426; `GetNativeDevice` ~1455; `RecordIssuedToken` device clause ~2194)
- Modify: `internal/store/models.go` (`NativeDevice` ~94, `DeviceBinding` ~221)
- Test: `internal/store/store_test.go`

**Interfaces:**
- Produces: `NativeDevice.AttestedLevel string` (json `attestedLevel`, DB default `'none'`), `AttestedAt *time.Time` (json `attestedAt,omitempty`), `BootState string` (json `bootState`, default `'unknown'`), `AttestationSerials []string` (json `-`, stored as JSON text); `DeviceBinding.AttestedLevel string`; `func (s *Store) SetNativeDeviceAttestation(deviceID, level, bootState string, serials []string, at time.Time) error`; `func (s *Store) ListAttestedDevices() ([]NativeDevice, error)` (level != none).

- [ ] **Step 1: Write the failing tests**

Append to `internal/store/store_test.go`:

```go
func TestAttestationColumnsMigrateAndRoundTrip(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	for _, col := range []string{"attested_level", "attested_at", "boot_state", "attestation_serials"} {
		var n int
		if err := s.db.QueryRow(`SELECT count(*) FROM pragma_table_info('native_devices') WHERE name = ?`, col).Scan(&n); err != nil || n != 1 {
			t.Fatalf("column %s missing: %d %v", col, n, err)
		}
	}
	u := createTestUser(t, s)
	dev := &NativeDevice{ID: "d1", UserID: u.ID, DeviceName: "p", DeviceIdentifier: "i", PublicKey: "pk", IsMFAApprover: true, CanSignOn: true}
	if err := s.UpsertNativeDevice(dev); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetNativeDevice("d1")
	if got.AttestedLevel != "none" || got.BootState != "unknown" || got.AttestedAt != nil {
		t.Fatalf("defaults: %+v", got)
	}
	at := time.Now().UTC().Truncate(time.Second)
	if err := s.SetNativeDeviceAttestation("d1", "tee", "locked-verified", []string{"0a1b", "ff"}, at); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetNativeDevice("d1")
	if got.AttestedLevel != "tee" || got.BootState != "locked-verified" || got.AttestedAt == nil || !got.AttestedAt.Equal(at) || len(got.AttestationSerials) != 2 {
		t.Fatalf("after set: %+v", got)
	}
	list, _ := s.ListUserNativeDevices(u.ID)
	if list[0].AttestedLevel != "tee" {
		t.Fatalf("list: %+v", list[0])
	}
	attested, _ := s.ListAttestedDevices()
	if len(attested) != 1 || attested[0].ID != "d1" {
		t.Fatalf("attested: %+v", attested)
	}
	if err := s.SetNativeDeviceAttestation("d1", "none", "unlocked", nil, at); err != nil {
		t.Fatal(err)
	}
	attested, _ = s.ListAttestedDevices()
	if len(attested) != 0 {
		t.Fatal("downgraded device still listed")
	}
}

func TestRecordIssuedTokenChecksAttestedLevel(t *testing.T) {
	// Reuse the fixture the existing device-binding test uses (grep TestRecordIssuedToken in this file);
	// register a device with attested_level tee, then attempt RecordIssuedToken with
	// Device{..., AttestedLevel: "tee"} → 1 row; downgrade to none; same call → ErrAppAccessDenied.
}
```

Fill the second test body by copying the existing device-binding token test's setup (user, client, app access, session) and adding the two assertions described in its comment; the comment must not remain.

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/store/ -run 'TestAttestation|TestRecordIssuedTokenChecksAttested' -count=1`
Expected: FAIL (undefined fields/methods).

- [ ] **Step 3: Implement**

DDL: add after `can_sign_on`:

```sql
		attested_level TEXT NOT NULL DEFAULT 'none',
		attested_at DATETIME,
		boot_state TEXT NOT NULL DEFAULT 'unknown',
		attestation_serials TEXT NOT NULL DEFAULT '[]',
```

Migrations, after `migrateDevicePairingTokenSignOn` in the chain:

```go
func (s *Store) migrateNativeDeviceAttestation() error {
	for _, m := range []struct{ col, alter string }{
		{"attested_level", `ALTER TABLE native_devices ADD COLUMN attested_level TEXT NOT NULL DEFAULT 'none'`},
		{"attested_at", `ALTER TABLE native_devices ADD COLUMN attested_at DATETIME`},
		{"boot_state", `ALTER TABLE native_devices ADD COLUMN boot_state TEXT NOT NULL DEFAULT 'unknown'`},
		{"attestation_serials", `ALTER TABLE native_devices ADD COLUMN attestation_serials TEXT NOT NULL DEFAULT '[]'`},
	} {
		if err := s.addColumnIfMissing("native_devices", m.col, m.alter); err != nil {
			return err
		}
	}
	return nil
}
```

Models:

```go
	CanSignOn            bool       `json:"canSignOn"`
	AttestedLevel        string     `json:"attestedLevel"` // none | tee | strongbox
	AttestedAt           *time.Time `json:"attestedAt,omitempty"`
	BootState            string     `json:"bootState"` // locked-verified | locked-selfsigned | unlocked | unknown
	AttestationSerials   []string   `json:"-"`
```

```go
type DeviceBinding struct {
	ID, UserID, PublicKey string
	AttestedLevel         string // the level the grant evaluated; the INSERT refuses if it changed
}
```

Column lists: add `attested_level, attested_at, boot_state, attestation_serials` to the SELECTs in `ListUserNativeDevices` and `GetNativeDevice` and scan into `&dev.AttestedLevel, &attestedAt (sql.NullTime), &dev.BootState, &serialsJSON (string)`; unmarshal `serialsJSON` into `dev.AttestationSerials` (empty on `[]`). The two INSERT/upsert statements do NOT set these columns (registration sets them through `SetNativeDeviceAttestation` right after; a re-pair conflict-update must reset them — add `attested_level='none', attested_at=NULL, boot_state='unknown', attestation_serials='[]'` to both `ON CONFLICT DO UPDATE SET` lists so a re-pair without attestation cannot inherit the old grade).

New store methods:

```go
func (s *Store) SetNativeDeviceAttestation(deviceID, level, bootState string, serials []string, at time.Time) error {
	if serials == nil {
		serials = []string{}
	}
	raw, err := json.Marshal(serials)
	if err != nil {
		return err
	}
	var attestedAt any
	if level != "none" {
		attestedAt = at.UTC()
	}
	_, err = s.db.Exec(`UPDATE native_devices SET attested_level=?, attested_at=?, boot_state=?, attestation_serials=? WHERE id=?`, level, attestedAt, bootState, string(raw), deviceID)
	return err
}

func (s *Store) ListAttestedDevices() ([]NativeDevice, error) {
	// same SELECT/scan as ListUserNativeDevices with WHERE attested_level <> 'none'
}
```

`RecordIssuedToken`: change the device clause to `... AND d.can_sign_on AND d.is_mfa_approver AND d.attested_level=?))` and append `d.AttestedLevel` to the args right after `d.PublicKey`. Update the placeholder count comment if one exists.

- [ ] **Step 4: Run store tests**

Run: `go test ./internal/store/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store
git commit -m "feat(store): attested level, boot state and serials on native devices"
```

---

### Task 2: `internal/attest` — KeyDescription decoder

**Files:**
- Create: `internal/attest/keydescription.go`
- Create: `internal/attest/keydescription_test.go`
- Create: `internal/attest/testenc_test.go` (DER builders shared by Tasks 2 and 3)

**Interfaces:**
- Produces:

```go
package attest

var ExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

const (SecurityLevelSoftware = 0; SecurityLevelTEE = 1; SecurityLevelStrongBox = 2)

type AuthList struct {
	Purpose        []int
	Algorithm      *int
	ECCurve        *int
	NoAuthRequired bool
	UserAuthType   *uint64
	AuthTimeout    *int
	Origin         *int
	RootOfTrust    *RootOfTrust
	AppID          *AppID
}
type RootOfTrust struct{ VerifiedBootKey []byte; DeviceLocked bool; VerifiedBootState int; VerifiedBootHash []byte }
type AppID struct{ Packages map[string]int64; SignatureDigests [][]byte }
type KeyDescription struct {
	AttestationVersion, KeyMintVersion             int
	AttestationSecurityLevel, KeyMintSecurityLevel int
	Challenge, UniqueID                            []byte
	Software, Hardware                             AuthList
}
func ParseKeyDescription(der []byte) (*KeyDescription, error)
```

- [ ] **Step 1: Write the DER builders and the failing tests**

`testenc_test.go` — builders that produce exactly the structures the spec names, used by every test in the package:

```go
package attest

import (
	"encoding/asn1"
	"math/big"
	"testing"
)

type tag struct {
	n   int
	der []byte
}

func mustMarshal(t *testing.T, v any, params string) []byte {
	t.Helper()
	b, err := asn1.MarshalWithParams(v, params)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// explicitTag wraps inner DER in [n] EXPLICIT.
func explicitTag(t *testing.T, n int, inner []byte) []byte {
	t.Helper()
	return mustMarshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: n, IsCompound: true, Bytes: inner}, "")
}

func intTag(t *testing.T, n int, v int64) []byte    { return explicitTag(t, n, mustMarshal(t, big.NewInt(v), "")) }
func nullTag(t *testing.T, n int) []byte            { return explicitTag(t, n, mustMarshal(t, asn1.NullRawValue, "")) }
func setOfIntTag(t *testing.T, n int, vs ...int) []byte { return explicitTag(t, n, mustMarshal(t, vs, "set")) }
func octetTag(t *testing.T, n int, b []byte) []byte  { return explicitTag(t, n, mustMarshal(t, b, "")) }

type rotDER struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState asn1.Enumerated
	VerifiedBootHash  []byte
}

func rootOfTrustTag(t *testing.T, locked bool, state int) []byte {
	return explicitTag(t, 704, mustMarshal(t, rotDER{make([]byte, 32), locked, asn1.Enumerated(state), make([]byte, 32)}, ""))
}

type pkgDER struct {
	Name    []byte
	Version int64
}
type appIDDER struct {
	Packages []pkgDER `asn1:"set"`
	Digests  [][]byte `asn1:"set"`
}

func appIDTag(t *testing.T, pkg string, digest []byte) []byte {
	inner := mustMarshal(t, appIDDER{[]pkgDER{{[]byte(pkg), 1}}, [][]byte{digest}}, "")
	return octetTag(t, 709, inner) // attestationApplicationId is an OCTET STRING holding DER
}

// authList concatenates already-tagged elements into a SEQUENCE.
func authList(t *testing.T, tags ...[]byte) []byte {
	var body []byte
	for _, x := range tags {
		body = append(body, x...)
	}
	return mustMarshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body}, "")
}

type kdOpts struct {
	attLevel, kmLevel int
	challenge         []byte
	hardware, software []byte // pre-built AuthorizationList DER
}

func keyDescriptionDER(t *testing.T, o kdOpts) []byte {
	t.Helper()
	var body []byte
	body = append(body, mustMarshal(t, big.NewInt(300), "")...)                  // attestationVersion
	body = append(body, mustMarshal(t, asn1.Enumerated(o.attLevel), "")...)    // attestationSecurityLevel
	body = append(body, mustMarshal(t, big.NewInt(300), "")...)                  // keyMintVersion
	body = append(body, mustMarshal(t, asn1.Enumerated(o.kmLevel), "")...)     // keyMintSecurityLevel
	body = append(body, mustMarshal(t, o.challenge, "")...)                      // attestationChallenge
	body = append(body, mustMarshal(t, []byte{}, "")...)                         // uniqueId
	body = append(body, o.software...)
	body = append(body, o.hardware...)
	return mustMarshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body}, "")
}

// goodHardware is the list a KyAuth per-use key produces.
func goodHardware(t *testing.T) []byte {
	return authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 3), intTag(t, 702, 0), rootOfTrustTag(t, true, 0))
}

func goodSoftware(t *testing.T, digest []byte) []byte {
	return authList(t, appIDTag(t, "org.kysecurity.authenticator", digest))
}
```

`keydescription_test.go`:

```go
package attest

import (
	"bytes"
	"testing"
)

func TestParseKeyDescriptionRoundTrip(t *testing.T) {
	digest := bytes.Repeat([]byte{0xab}, 32)
	der := keyDescriptionDER(t, kdOpts{attLevel: 2, kmLevel: 2, challenge: []byte("chal"), hardware: goodHardware(t), software: goodSoftware(t, digest)})
	kd, err := ParseKeyDescription(der)
	if err != nil {
		t.Fatal(err)
	}
	if kd.AttestationSecurityLevel != 2 || kd.KeyMintSecurityLevel != 2 || string(kd.Challenge) != "chal" {
		t.Fatalf("%+v", kd)
	}
	h := kd.Hardware
	if len(h.Purpose) != 1 || h.Purpose[0] != 2 || *h.Algorithm != 3 || *h.ECCurve != 1 || *h.UserAuthType != 3 || h.AuthTimeout != nil || h.NoAuthRequired || *h.Origin != 0 {
		t.Fatalf("hardware: %+v", h)
	}
	if h.RootOfTrust == nil || !h.RootOfTrust.DeviceLocked || h.RootOfTrust.VerifiedBootState != 0 {
		t.Fatalf("rot: %+v", h.RootOfTrust)
	}
	if kd.Software.AppID == nil || kd.Software.AppID.Packages["org.kysecurity.authenticator"] != 1 || !bytes.Equal(kd.Software.AppID.SignatureDigests[0], digest) {
		t.Fatalf("appid: %+v", kd.Software.AppID)
	}
}

func TestParseKeyDescriptionUserAuthTypeAny(t *testing.T) {
	hw := authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 0xFFFFFFFF), intTag(t, 702, 0))
	kd, err := ParseKeyDescription(keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: []byte("c"), hardware: hw, software: authList(t)}))
	if err != nil || kd.Hardware.UserAuthType == nil || *kd.Hardware.UserAuthType != 0xFFFFFFFF {
		t.Fatalf("%v %+v", err, kd)
	}
}

func TestParseKeyDescriptionTimeoutAndNoAuth(t *testing.T) {
	hw := authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 2), intTag(t, 505, 30), nullTag(t, 503), intTag(t, 702, 0))
	kd, err := ParseKeyDescription(keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: []byte("c"), hardware: hw, software: authList(t)}))
	if err != nil || kd.Hardware.AuthTimeout == nil || *kd.Hardware.AuthTimeout != 30 || !kd.Hardware.NoAuthRequired {
		t.Fatalf("%v %+v", err, kd)
	}
}

func TestParseKeyDescriptionRejectsGarbage(t *testing.T) {
	for _, in := range [][]byte{nil, {0x30}, {0x04, 0x01, 0x00}, bytes.Repeat([]byte{0x30, 0x80}, 3)} {
		if _, err := ParseKeyDescription(in); err == nil {
			t.Fatalf("accepted %x", in)
		}
	}
}

func TestParseKeyDescriptionIgnoresUnknownTags(t *testing.T) {
	hw := authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 2), intTag(t, 702, 0), intTag(t, 705, 140000), intTag(t, 999, 1))
	if _, err := ParseKeyDescription(keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: []byte("c"), hardware: hw, software: authList(t)})); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/attest/ -count=1`
Expected: FAIL, undefined `ParseKeyDescription`.

- [ ] **Step 3: Implement**

`keydescription.go`:

```go
// Package attest verifies Android Key Attestation chains for native-device registration.
package attest

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

var ExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

const (
	SecurityLevelSoftware  = 0
	SecurityLevelTEE       = 1
	SecurityLevelStrongBox = 2
)

type RootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState int // 0 Verified, 1 SelfSigned, 2 Unverified, 3 Failed
	VerifiedBootHash  []byte
}

type AppID struct {
	Packages         map[string]int64
	SignatureDigests [][]byte
}

type AuthList struct {
	Purpose        []int
	Algorithm      *int
	ECCurve        *int
	NoAuthRequired bool
	UserAuthType   *uint64
	AuthTimeout    *int
	Origin         *int
	RootOfTrust    *RootOfTrust
	AppID          *AppID
}

type KeyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel int
	KeyMintVersion           int
	KeyMintSecurityLevel     int
	Challenge                []byte
	UniqueID                 []byte
	Software                 AuthList
	Hardware                 AuthList
}

// keyDescriptionDER mirrors the wire SEQUENCE; the two lists are kept raw and walked by hand
// because their members are EXPLICIT context tags with arbitrary numbers.
type keyDescriptionDER struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeyMintVersion           int
	KeyMintSecurityLevel     asn1.Enumerated
	Challenge                []byte
	UniqueID                 []byte
	Software                 asn1.RawValue
	Hardware                 asn1.RawValue
}

func ParseKeyDescription(der []byte) (*KeyDescription, error) {
	var kd keyDescriptionDER
	rest, err := asn1.Unmarshal(der, &kd)
	if err != nil {
		return nil, fmt.Errorf("key description: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("key description: trailing bytes")
	}
	sw, err := parseAuthList(kd.Software)
	if err != nil {
		return nil, fmt.Errorf("softwareEnforced: %w", err)
	}
	hw, err := parseAuthList(kd.Hardware)
	if err != nil {
		return nil, fmt.Errorf("hardwareEnforced: %w", err)
	}
	return &KeyDescription{
		AttestationVersion: kd.AttestationVersion, AttestationSecurityLevel: int(kd.AttestationSecurityLevel),
		KeyMintVersion: kd.KeyMintVersion, KeyMintSecurityLevel: int(kd.KeyMintSecurityLevel),
		Challenge: kd.Challenge, UniqueID: kd.UniqueID, Software: sw, Hardware: hw,
	}, nil
}

func parseAuthList(seq asn1.RawValue) (AuthList, error) {
	var out AuthList
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return out, errors.New("not a SEQUENCE")
	}
	rest := seq.Bytes
	for len(rest) > 0 {
		var rv asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &rv)
		if err != nil {
			return out, err
		}
		if rv.Class != asn1.ClassContextSpecific || !rv.IsCompound {
			return out, fmt.Errorf("unexpected element class %d", rv.Class)
		}
		switch rv.Tag {
		case 1:
			var vs []int
			if _, err := asn1.UnmarshalWithParams(rv.Bytes, &vs, "set"); err != nil {
				return out, fmt.Errorf("purpose: %w", err)
			}
			out.Purpose = vs
		case 2:
			out.Algorithm, err = smallInt(rv.Bytes)
		case 10:
			out.ECCurve, err = smallInt(rv.Bytes)
		case 503:
			out.NoAuthRequired = true
		case 504:
			var n *big.Int
			if _, err = asn1.Unmarshal(rv.Bytes, &n); err == nil {
				if n.Sign() < 0 || n.BitLen() > 64 {
					err = errors.New("userAuthType out of range")
				} else {
					v := n.Uint64()
					out.UserAuthType = &v
				}
			}
		case 505:
			out.AuthTimeout, err = smallInt(rv.Bytes)
		case 702:
			out.Origin, err = smallInt(rv.Bytes)
		case 704:
			var r struct {
				VerifiedBootKey   []byte
				DeviceLocked      bool
				VerifiedBootState asn1.Enumerated
				VerifiedBootHash  []byte `asn1:"optional"`
			}
			if _, err = asn1.Unmarshal(rv.Bytes, &r); err == nil {
				out.RootOfTrust = &RootOfTrust{r.VerifiedBootKey, r.DeviceLocked, int(r.VerifiedBootState), r.VerifiedBootHash}
			}
		case 709:
			var octets []byte
			if _, err = asn1.Unmarshal(rv.Bytes, &octets); err == nil {
				out.AppID, err = parseAppID(octets)
			}
		}
		if err != nil {
			return out, fmt.Errorf("tag %d: %w", rv.Tag, err)
		}
	}
	return out, nil
}

func smallInt(der []byte) (*int, error) {
	var v int
	if _, err := asn1.Unmarshal(der, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func parseAppID(der []byte) (*AppID, error) {
	var raw struct {
		Packages []struct {
			Name    []byte
			Version int64
		} `asn1:"set"`
		Digests [][]byte `asn1:"set"`
	}
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return nil, err
	}
	out := &AppID{Packages: map[string]int64{}, SignatureDigests: raw.Digests}
	for _, p := range raw.Packages {
		out.Packages[string(p.Name)] = p.Version
	}
	return out, nil
}
```

If `asn1` refuses `[]int` with `"set"` for the purpose list, unmarshal into an `asn1.RawValue` and iterate its `Bytes` with `smallInt` the same way the outer loop does.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/attest/ -count=1`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/attest
git commit -m "feat(attest): decode the Android key attestation extension"
```

---

### Task 3: `internal/attest` — chain, roots, status, `Verify`

**Files:**
- Create: `internal/attest/verify.go`
- Create: `internal/attest/roots.go` + `internal/attest/roots.json` (embedded)
- Create: `internal/attest/status.go`
- Create: `internal/attest/verify_test.go`, `internal/attest/testca_test.go`

**Interfaces:**
- Produces:

```go
type Expectation struct {
	Challenge               []byte
	PublicKeySPKI           []byte   // DER SubjectPublicKeyInfo of the registered key
	AppPackage              string
	AppDigests              [][]byte // SHA-256 of signing certs
	RequireLockedBootloader bool
	Now                     time.Time
}
type Result struct {
	Level     string // none | tee | strongbox
	Reason    string // empty when Level != none
	BootState string // locked-verified | locked-selfsigned | unlocked | unknown
	Serials   []string
}
type Roots interface{ Pool() (*x509.CertPool, []*x509.Certificate) }
type Status interface{ Revoked(serialHex string) (revoked bool, known bool) }
func Verify(chainDER [][]byte, want Expectation, roots Roots, status Status) Result

const LegacyRSARootSerialNumber = "f92009e853b6b045" // subject SERIALNUMBER attribute

func LoadEmbeddedRoots() (*StaticRoots, error)          // roots.json (go:embed)
func LoadExtraRoots(pemPath string) ([]*x509.Certificate, error)
type StaticRoots struct{ certs []*x509.Certificate }  // implements Roots
func NewRefreshingRoots(static *StaticRoots, url string, fetch func(url string) ([]byte, http.Header, error)) *RefreshingRoots // daily refresh; implements Roots
type StatusList struct{...}  // implements Status; NewStatusList(url string, fetch func(url string) ([]byte, http.Header, error), disabled bool)
func (s *StatusList) Refresh() error   // honours max-age; called by the sweep and lazily on first use
```

- [ ] **Step 1: Test CA and failing tests**

`testca_test.go` builds an in-process chain: root (self-signed ECDSA P-256), intermediate, attestation leaf with the extension. The leaf's public key is a fresh P-256 key (the "device key"); the extension is `keyDescriptionDER(...)` from Task 2's builders.

```go
package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

type testCA struct {
	root, inter         *x509.Certificate
	rootKey, interKey   *ecdsa.PrivateKey
	rootDER, interDER   []byte
}

func newTestCA(t *testing.T, rootSubjectSerial string, notAfter time.Time) *testCA {
	t.Helper()
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root", SerialNumber: rootSubjectSerial},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rk.PublicKey, rk)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	ik, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, &ik.PublicKey, rk)
	if err != nil {
		t.Fatal(err)
	}
	inter, _ := x509.ParseCertificate(interDER)
	return &testCA{root, inter, rk, ik, rootDER, interDER}
}

// leaf signs a device key with the attestation extension carrying kdDER. serial distinguishes leaves.
func (c *testCA) leaf(t *testing.T, devicePub *ecdsa.PublicKey, kdDER []byte, serial int64, notAfter time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Android Keystore Key"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		ExtraExtensions: []pkix.Extension{{Id: ExtensionOID, Value: kdDER}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.inter, devicePub, c.interKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

type staticStatus map[string]bool

func (s staticStatus) Revoked(serial string) (bool, bool) { return s[serial], true }

func spki(t *testing.T, pub *ecdsa.PublicKey) []byte {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var _ = asn1.ClassUniversal // keep import if unused in this file
```

`verify_test.go`:

```go
package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

var digest = bytes.Repeat([]byte{0xab}, 32)

func good(t *testing.T) (*testCA, *ecdsa.PrivateKey, [][]byte, Expectation) {
	ca := newTestCA(t, "testroot", time.Now().Add(time.Hour))
	dev, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	chal := []byte("challenge-1")
	kd := keyDescriptionDER(t, kdOpts{attLevel: 2, kmLevel: 2, challenge: chal, hardware: goodHardware(t), software: goodSoftware(t, digest)})
	leaf := ca.leaf(t, &dev.PublicKey, kd, 100, time.Now().Add(time.Hour))
	want := Expectation{Challenge: chal, PublicKeySPKI: spki(t, &dev.PublicKey), AppPackage: "org.kysecurity.authenticator", AppDigests: [][]byte{digest}, Now: time.Now()}
	return ca, dev, [][]byte{leaf, ca.interDER, ca.rootDER}, want
}

func roots(ca *testCA) *StaticRoots { return &StaticRoots{certs: []*x509.Certificate{ca.root}} }

func TestVerifyStrongBoxChain(t *testing.T) {
	ca, _, chain, want := good(t)
	r := Verify(chain, want, roots(ca), staticStatus{})
	if r.Level != "strongbox" || r.Reason != "" || r.BootState != "locked-verified" || len(r.Serials) != 3 {
		t.Fatalf("%+v", r)
	}
}

func TestVerifyRefusals(t *testing.T) {
	type mut func(t *testing.T, ca *testCA, dev *ecdsa.PrivateKey, chain [][]byte, want *Expectation) ([][]byte, Roots, Status)
	cases := map[string]mut{
		"untrusted root": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			other := newTestCA(t, "other", time.Now().Add(time.Hour))
			return c, roots(other), staticStatus{}
		},
		"broken signature": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			bad := append([]byte{}, c[0]...)
			bad[len(bad)-1] ^= 0x01
			return [][]byte{bad, c[1], c[2]}, roots(ca), staticStatus{}
		},
		"revoked intermediate": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			return c, roots(ca), staticStatus{"2": true}
		},
		"status unknown": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			return c, roots(ca), unknownStatus{}
		},
		"challenge mismatch": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			w.Challenge = []byte("other")
			return c, roots(ca), staticStatus{}
		},
		"key mismatch": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			o, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			w.PublicKeySPKI = spki(t, &o.PublicKey)
			return c, roots(ca), staticStatus{}
		},
		"software level": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			kd := keyDescriptionDER(t, kdOpts{attLevel: 0, kmLevel: 0, challenge: w.Challenge, hardware: goodHardware(t), software: goodSoftware(t, digest)})
			return [][]byte{ca.leaf(t, &d.PublicKey, kd, 101, time.Now().Add(time.Hour)), c[1], c[2]}, roots(ca), staticStatus{}
		},
		"levels differ": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			kd := keyDescriptionDER(t, kdOpts{attLevel: 2, kmLevel: 1, challenge: w.Challenge, hardware: goodHardware(t), software: goodSoftware(t, digest)})
			return [][]byte{ca.leaf(t, &d.PublicKey, kd, 102, time.Now().Add(time.Hour)), c[1], c[2]}, roots(ca), staticStatus{}
		},
		"auth timeout": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			hw := authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 3), intTag(t, 505, 30), intTag(t, 702, 0))
			kd := keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: w.Challenge, hardware: hw, software: goodSoftware(t, digest)})
			return [][]byte{ca.leaf(t, &d.PublicKey, kd, 103, time.Now().Add(time.Hour)), c[1], c[2]}, roots(ca), staticStatus{}
		},
		"no auth required": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			hw := authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), nullTag(t, 503), intTag(t, 702, 0))
			kd := keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: w.Challenge, hardware: hw, software: goodSoftware(t, digest)})
			return [][]byte{ca.leaf(t, &d.PublicKey, kd, 104, time.Now().Add(time.Hour)), c[1], c[2]}, roots(ca), staticStatus{}
		},
		"user auth only in software list": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			hw := authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 702, 0))
			sw := authList(t, appIDTag(t, "org.kysecurity.authenticator", digest), intTag(t, 504, 3))
			kd := keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: w.Challenge, hardware: hw, software: sw})
			return [][]byte{ca.leaf(t, &d.PublicKey, kd, 105, time.Now().Add(time.Hour)), c[1], c[2]}, roots(ca), staticStatus{}
		},
		"imported origin": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			hw := authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 3), intTag(t, 702, 2))
			kd := keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: w.Challenge, hardware: hw, software: goodSoftware(t, digest)})
			return [][]byte{ca.leaf(t, &d.PublicKey, kd, 106, time.Now().Add(time.Hour)), c[1], c[2]}, roots(ca), staticStatus{}
		},
		"wrong package": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			kd := keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: w.Challenge, hardware: goodHardware(t), software: goodSoftware(t, digest)})
			w.AppPackage = "com.evil"
			return [][]byte{ca.leaf(t, &d.PublicKey, kd, 107, time.Now().Add(time.Hour)), c[1], c[2]}, roots(ca), staticStatus{}
		},
		"wrong digest": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			w.AppDigests = [][]byte{bytes.Repeat([]byte{0xcd}, 32)}
			return c, roots(ca), staticStatus{}
		},
		"extension twice": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			// Put the extension on the intermediate too: the first occurrence from the root is the
			// intermediate, whose key is not the device key, and a second occurrence must reject.
			inter2 := ca.reissueIntermediateWithExtension(t, keyDescriptionDER(t, kdOpts{attLevel: 2, kmLevel: 2, challenge: w.Challenge, hardware: goodHardware(t), software: goodSoftware(t, digest)}))
			return [][]byte{c[0], inter2, c[2]}, roots(ca), staticStatus{}
		},
		"expired leaf under non-legacy root": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			kd := keyDescriptionDER(t, kdOpts{attLevel: 2, kmLevel: 2, challenge: w.Challenge, hardware: goodHardware(t), software: goodSoftware(t, digest)})
			return [][]byte{ca.leaf(t, &d.PublicKey, kd, 108, time.Now().Add(-time.Minute)), c[1], c[2]}, roots(ca), staticStatus{}
		},
		"unlocked with setting on": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			hw := authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 3), intTag(t, 702, 0), rootOfTrustTag(t, false, 2))
			kd := keyDescriptionDER(t, kdOpts{attLevel: 2, kmLevel: 2, challenge: w.Challenge, hardware: hw, software: goodSoftware(t, digest)})
			w.RequireLockedBootloader = true
			return [][]byte{ca.leaf(t, &d.PublicKey, kd, 109, time.Now().Add(time.Hour)), c[1], c[2]}, roots(ca), staticStatus{}
		},
		"empty chain": func(t *testing.T, ca *testCA, d *ecdsa.PrivateKey, c [][]byte, w *Expectation) ([][]byte, Roots, Status) {
			return nil, roots(ca), staticStatus{}
		},
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			ca, dev, chain, want := good(t)
			chain, rs, st := m(t, ca, dev, chain, &want)
			r := Verify(chain, want, rs, st)
			if r.Level != "none" || r.Reason == "" {
				t.Fatalf("%s: %+v", name, r)
			}
		})
	}
}

func TestVerifyUnlockedRecordedWhenSettingOff(t *testing.T) {
	ca, dev, chain, want := good(t)
	hw := authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 3), intTag(t, 702, 0), rootOfTrustTag(t, false, 2))
	kd := keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: want.Challenge, hardware: hw, software: goodSoftware(t, digest)})
	chain = [][]byte{ca.leaf(t, &dev.PublicKey, kd, 110, time.Now().Add(time.Hour)), chain[1], chain[2]}
	r := Verify(chain, want, roots(ca), staticStatus{})
	if r.Level != "tee" || r.BootState != "unlocked" {
		t.Fatalf("%+v", r)
	}
	selfSigned := authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 3), intTag(t, 702, 0), rootOfTrustTag(t, true, 1))
	kd = keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: want.Challenge, hardware: selfSigned, software: goodSoftware(t, digest)})
	want.RequireLockedBootloader = true
	r = Verify([][]byte{ca.leaf(t, &dev.PublicKey, kd, 111, time.Now().Add(time.Hour)), chain[1], chain[2]}, want, roots(ca), staticStatus{})
	if r.Level != "tee" || r.BootState != "locked-selfsigned" {
		t.Fatalf("self-signed locked must pass: %+v", r)
	}
}

func TestVerifyLegacyRootAcceptsExpiredChain(t *testing.T) {
	ca := newTestCA(t, LegacyRSARootSerialNumber, time.Now().Add(-time.Minute)) // root and intermediate already expired
	dev, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	chal := []byte("c")
	kd := keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: chal, hardware: goodHardware(t), software: goodSoftware(t, digest)})
	leaf := ca.leaf(t, &dev.PublicKey, kd, 200, time.Now().Add(-time.Minute))
	want := Expectation{Challenge: chal, PublicKeySPKI: spki(t, &dev.PublicKey), AppPackage: "org.kysecurity.authenticator", AppDigests: [][]byte{digest}, Now: time.Now()}
	if r := Verify([][]byte{leaf, ca.interDER, ca.rootDER}, want, roots(ca), staticStatus{}); r.Level != "tee" {
		t.Fatalf("%+v", r)
	}
}

func TestVerifyChainWithoutRootCert(t *testing.T) {
	ca, _, chain, want := good(t)
	if r := Verify(chain[:2], want, roots(ca), staticStatus{}); r.Level != "strongbox" {
		t.Fatalf("chain ending at intermediate signed by a trusted root must pass: %+v", r)
	}
}

type unknownStatus struct{}

func (unknownStatus) Revoked(string) (bool, bool) { return false, false }
```

Add to `testca_test.go` a `reissueIntermediateWithExtension(t, kdDER) []byte` that recreates the intermediate template with `ExtraExtensions` carrying the OID, signed by the root, keeping `interKey` so the existing leaf still chains.

Also the embedded roots test (in `verify_test.go`):

```go
func TestEmbeddedRootsParse(t *testing.T) {
	r, err := LoadEmbeddedRoots()
	if err != nil {
		t.Fatal(err)
	}
	_, certs := r.Pool()
	found := false
	for _, c := range certs {
		if c.Subject.SerialNumber == LegacyRSARootSerialNumber {
			found = true
		}
	}
	if !found {
		t.Fatalf("legacy RSA root not embedded; subjects: %v", certs)
	}
}
```

- [ ] **Step 2: Fetch and embed Google's roots**

Run: `curl -fsS https://android.googleapis.com/attestation/root -o internal/attest/roots.json && python3 -c "import json;d=json.load(open('internal/attest/roots.json'));print(type(d).__name__, len(d))"`
Expected: `list 2` (or more). If the endpoint's shape is not a JSON array of PEM strings, adapt `LoadEmbeddedRoots` to the real shape and note it in the report.

- [ ] **Step 3: Run to verify tests fail**

Run: `go test ./internal/attest/ -count=1`
Expected: FAIL, undefined `Verify`, `StaticRoots`, etc.

- [ ] **Step 4: Implement roots, status, verify**

`roots.go`:

```go
package attest

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	_ "embed"
)

//go:embed roots.json
var embeddedRootsJSON []byte

const LegacyRSARootSerialNumber = "f92009e853b6b045"

type Roots interface {
	Pool() (*x509.CertPool, []*x509.Certificate)
}

type StaticRoots struct{ certs []*x509.Certificate }

func (s *StaticRoots) Pool() (*x509.CertPool, []*x509.Certificate) {
	p := x509.NewCertPool()
	for _, c := range s.certs {
		p.AddCert(c)
	}
	return p, s.certs
}

func parsePEMs(pems []string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, s := range pems {
		rest := []byte(s)
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no certificates")
	}
	return out, nil
}

func LoadEmbeddedRoots() (*StaticRoots, error) {
	var pems []string
	if err := json.Unmarshal(embeddedRootsJSON, &pems); err != nil {
		return nil, fmt.Errorf("embedded roots: %w", err)
	}
	certs, err := parsePEMs(pems)
	if err != nil {
		return nil, err
	}
	return &StaticRoots{certs: certs}, nil
}

func LoadExtraRoots(path string) ([]*x509.Certificate, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parsePEMs([]string{string(raw)})
}

// RefreshingRoots serves the embedded and extra roots plus whatever the root endpoint published
// at the last successful refresh. A failed refresh keeps the previous set.
type RefreshingRoots struct {
	mu      sync.RWMutex
	base    []*x509.Certificate
	fetched []*x509.Certificate
	url     string
	fetch   func(url string) ([]byte, http.Header, error)
	last    time.Time
}

func NewRefreshingRoots(base []*x509.Certificate, url string, fetch func(string) ([]byte, http.Header, error)) *RefreshingRoots {
	return &RefreshingRoots{base: base, url: url, fetch: fetch}
}

func (r *RefreshingRoots) Refresh() error {
	if r.url == "" {
		return nil
	}
	body, _, err := r.fetch(r.url)
	if err != nil {
		return err
	}
	var pems []string
	if err := json.Unmarshal(body, &pems); err != nil {
		return err
	}
	certs, err := parsePEMs(pems)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.fetched, r.last = certs, time.Now()
	r.mu.Unlock()
	return nil
}

func (r *RefreshingRoots) Pool() (*x509.CertPool, []*x509.Certificate) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	all := append(append([]*x509.Certificate{}, r.base...), r.fetched...)
	p := x509.NewCertPool()
	for _, c := range all {
		p.AddCert(c)
	}
	return p, all
}
```

`status.go`:

```go
package attest

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Status interface {
	// Revoked reports whether serialHex (lowercase, no leading zeros) is revoked or suspended, and
	// whether the answer is backed by a usable list at all.
	Revoked(serialHex string) (revoked bool, known bool)
}

type StatusList struct {
	mu       sync.RWMutex
	url      string
	fetch    func(url string) ([]byte, http.Header, error)
	disabled bool
	entries  map[string]struct{}
	loadedAt time.Time
	maxAge   time.Duration
}

func NewStatusList(url string, fetch func(string) ([]byte, http.Header, error)) *StatusList {
	return &StatusList{url: url, fetch: fetch, disabled: url == "", maxAge: 24 * time.Hour}
}

func (s *StatusList) Refresh() error {
	if s.disabled {
		return nil
	}
	body, hdr, err := s.fetch(s.url)
	if err != nil {
		return err
	}
	var doc struct {
		Entries map[string]struct {
			Status string `json:"status"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return err
	}
	if doc.Entries == nil {
		return errors.New("status list without entries")
	}
	set := make(map[string]struct{}, len(doc.Entries))
	for serial, e := range doc.Entries {
		if e.Status == "REVOKED" || e.Status == "SUSPENDED" {
			set[strings.ToLower(serial)] = struct{}{}
		}
	}
	maxAge := 24 * time.Hour
	for _, part := range strings.Split(hdr.Get("Cache-Control"), ",") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(part), "max-age="); ok {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				maxAge = time.Duration(n) * time.Second
			}
		}
	}
	s.mu.Lock()
	s.entries, s.loadedAt, s.maxAge = set, time.Now(), maxAge
	s.mu.Unlock()
	return nil
}

func (s *StatusList) Stale() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.entries == nil || time.Since(s.loadedAt) > s.maxAge
}

func (s *StatusList) Revoked(serialHex string) (bool, bool) {
	if s.disabled {
		return false, true // check disabled by the operator: every serial is "known good"
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.entries == nil {
		return false, false
	}
	_, hit := s.entries[strings.ToLower(strings.TrimLeft(serialHex, "0"))]
	return hit, true
}
```

`verify.go`:

```go
package attest

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"time"
)

type Expectation struct {
	Challenge               []byte
	PublicKeySPKI           []byte
	AppPackage              string
	AppDigests              [][]byte
	RequireLockedBootloader bool
	Now                     time.Time
}

type Result struct {
	Level     string
	Reason    string
	BootState string
	Serials   []string
}

func none(reason string, serials []string) Result {
	return Result{Level: "none", Reason: reason, BootState: "unknown", Serials: serials}
}

// Verify grades an attestation chain (leaf first). It never returns an error: every failure is a
// Result with Level "none" and a Reason for the audit log.
func Verify(chainDER [][]byte, want Expectation, roots Roots, status Status) Result {
	if len(chainDER) == 0 {
		return none("no chain", nil)
	}
	certs := make([]*x509.Certificate, 0, len(chainDER))
	for i, der := range chainDER {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return none(fmt.Sprintf("certificate %d: %v", i, err), nil)
		}
		certs = append(certs, c)
	}
	serials := make([]string, 0, len(certs))
	for _, c := range certs {
		serials = append(serials, fmt.Sprintf("%x", c.SerialNumber))
	}
	// 1. Chain to a trusted root.
	_, trusted := roots.Pool()
	root, err := chainToTrustedRoot(certs, trusted)
	if err != nil {
		return none(err.Error(), serials)
	}
	legacy := root.Subject.SerialNumber == LegacyRSARootSerialNumber
	if !legacy {
		for i, c := range certs {
			if want.Now.Before(c.NotBefore) || want.Now.After(c.NotAfter) {
				return none(fmt.Sprintf("certificate %d outside validity", i), serials)
			}
		}
	}
	// 2. Revocation.
	for _, s := range serials {
		revoked, known := status.Revoked(s)
		if !known {
			return none("status list unavailable", serials)
		}
		if revoked {
			return none("certificate "+s+" revoked", serials)
		}
	}
	// 3. First extension walking from the root; any later one rejects.
	var attCert *x509.Certificate
	for i := len(certs) - 1; i >= 0; i-- {
		if ext := findExt(certs[i]); ext != nil {
			if attCert != nil {
				return none("attestation extension appears more than once", serials)
			}
			attCert = certs[i]
		}
	}
	if attCert == nil {
		return none("no attestation extension", serials)
	}
	// 4. Key binding.
	if !bytes.Equal(attCert.RawSubjectPublicKeyInfo, want.PublicKeySPKI) {
		return none("attested key differs from registered key", serials)
	}
	kd, err := ParseKeyDescription(findExt(attCert))
	if err != nil {
		return none(err.Error(), serials)
	}
	// 5. Levels and challenge.
	lvl := kd.AttestationSecurityLevel
	if lvl != kd.KeyMintSecurityLevel || (lvl != SecurityLevelTEE && lvl != SecurityLevelStrongBox) {
		return none(fmt.Sprintf("security level %d/%d", kd.AttestationSecurityLevel, kd.KeyMintSecurityLevel), serials)
	}
	if !bytes.Equal(kd.Challenge, want.Challenge) {
		return none("challenge mismatch", serials)
	}
	// 6. Hardware-enforced key policy.
	hw := kd.Hardware
	if !contains(hw.Purpose, 2) || hw.Algorithm == nil || *hw.Algorithm != 3 || hw.ECCurve == nil || *hw.ECCurve != 1 {
		return none("key is not an EC P-256 signing key", serials)
	}
	if hw.Origin == nil || *hw.Origin != 0 {
		return none("key was not generated in hardware", serials)
	}
	if hw.NoAuthRequired || hw.UserAuthType == nil || *hw.UserAuthType == 0 || hw.AuthTimeout != nil {
		return none("key does not require per-use user authentication", serials)
	}
	boot := bootState(hw.RootOfTrust)
	// 7. Application identity.
	app := kd.Software.AppID
	if app == nil {
		return none("no attestation application id", serials)
	}
	if _, ok := app.Packages[want.AppPackage]; !ok {
		return none("attested app is not "+want.AppPackage, serials)
	}
	if !anyDigest(app.SignatureDigests, want.AppDigests) {
		return none("attested app signature not pinned", serials)
	}
	// 8. Locked bootloader policy.
	if want.RequireLockedBootloader && boot != "locked-verified" && boot != "locked-selfsigned" {
		return Result{Level: "none", Reason: "bootloader not locked (" + boot + ")", BootState: boot, Serials: serials}
	}
	level := "tee"
	if lvl == SecurityLevelStrongBox {
		level = "strongbox"
	}
	return Result{Level: level, BootState: boot, Serials: serials}
}

func chainToTrustedRoot(certs []*x509.Certificate, trusted []*x509.Certificate) (*x509.Certificate, error) {
	for i := 0; i+1 < len(certs); i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return nil, fmt.Errorf("certificate %d not signed by certificate %d", i, i+1)
		}
	}
	last := certs[len(certs)-1]
	for _, r := range trusted {
		if bytes.Equal(r.Raw, last.Raw) {
			return r, nil
		}
		if err := last.CheckSignatureFrom(r); err == nil {
			return r, nil
		}
	}
	return nil, fmt.Errorf("chain does not end at a trusted root")
}

func findExt(c *x509.Certificate) []byte {
	for _, e := range c.Extensions {
		if e.Id.Equal(ExtensionOID) {
			return e.Value
		}
	}
	return nil
}

func bootState(r *RootOfTrust) string {
	switch {
	case r == nil:
		return "unknown"
	case r.DeviceLocked && r.VerifiedBootState == 0:
		return "locked-verified"
	case r.DeviceLocked && r.VerifiedBootState == 1:
		return "locked-selfsigned"
	case !r.DeviceLocked:
		return "unlocked"
	default:
		return "unknown"
	}
}

func contains(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func anyDigest(have, want [][]byte) bool {
	for _, h := range have {
		for _, w := range want {
			if bytes.Equal(h, w) {
				return true
			}
		}
	}
	return false
}
```

`x509.ParseCertificate` may reject Google's real leaf certificates that carry unknown critical extensions or unusual fields; if `TestEmbeddedRootsParse` or a real fixture fails to parse, note it in the report. `CheckSignatureFrom` verifies signatures only (no validity), which is what step 1 needs since validity is handled explicitly.

- [ ] **Step 5: Run tests**

Run: `go test ./internal/attest/ -count=1 -race`
Expected: PASS (all cases incl. the 17-case refusal table).

- [ ] **Step 6: Commit**

```bash
git add internal/attest
git commit -m "feat(attest): verify Android key attestation chains against Google's roots"
```

---

### Task 4: Config, registration wiring, response, audit

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/mfa/mfa.go` (`NativeDeviceRegisterRequest`, `RegisterNativeDevice`, `Engine` fields / `NewEngine`)
- Modify: `internal/api/device_handlers.go` (`RegisterNativeDevice` body cap + audit details)
- Modify: `cmd/kyidentity/main.go` (construct roots/status; startup warning when the status URL is empty; pass into the mfa engine)
- Test: `internal/mfa/mfa_test.go`, `internal/api/device_signon_test.go` (or a new `device_attestation_test.go`)

**Interfaces:**
- Produces: `config.Config.AttestationExtraRoots string`, `.AttestationStatusURL string` (default `https://android.googleapis.com/attestation/status`), `.KyAuthCertSHA256 []string` (default one digest); `mfa.Attestor` interface `{ Verify(chain [][]byte, want attest.Expectation) attest.Result }` with `attest.NewVerifier(roots attest.Roots, status attest.Status, appPackage string, digests [][]byte, requireLocked func() bool) *Verifier` implementing it; `NativeDeviceRegisterRequest.Attestation []string` (json `attestation`); `func ExpectedChallenge(req *NativeDeviceRegisterRequest) []byte`; registration response `device.attestedLevel`, `device.bootState`.

- [ ] **Step 1: Write the failing tests**

`internal/mfa/mfa_test.go`:

```go
func TestExpectedChallengeMatchesKyAuth(t *testing.T) {
	tok := &NativeDeviceRegisterRequest{PairingToken: "abc123"}
	if got := ExpectedChallenge(tok); fmt.Sprintf("%x", got) != fmt.Sprintf("%x", sha256.Sum256([]byte("kyidentity-attest-v1|abc123"))) {
		t.Fatalf("token challenge %x", got)
	}
	pin := &NativeDeviceRegisterRequest{PINCode: "123456", UserID: "u1"}
	if got := ExpectedChallenge(pin); fmt.Sprintf("%x", got) != fmt.Sprintf("%x", sha256.Sum256([]byte("kyidentity-attest-v1|u1|123456"))) {
		t.Fatalf("pin challenge %x", got)
	}
	both := &NativeDeviceRegisterRequest{PairingToken: "tok", PINCode: "123456", UserID: "u1"}
	if fmt.Sprintf("%x", ExpectedChallenge(both)) != fmt.Sprintf("%x", ExpectedChallenge(tok)) && fmt.Sprintf("%x", ExpectedChallenge(both)) != fmt.Sprintf("%x", sha256.Sum256([]byte("kyidentity-attest-v1|tok"))) {
		t.Fatal("token must win when both present")
	}
}

type fakeAttestor struct {
	want   []byte
	result attest.Result
	calls  int
}

func (f *fakeAttestor) Verify(chain [][]byte, want attest.Expectation) attest.Result {
	f.calls++
	if !bytes.Equal(want.Challenge, f.want) {
		return attest.Result{Level: "none", Reason: "test: unexpected challenge", BootState: "unknown"}
	}
	return f.result
}

func TestRegisterNativeDeviceRecordsAttestation(t *testing.T) {
	engine, dbStore, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	token, _, _, _ := engine.GenerateDevicePairingToken(user.ID, true)
	fa := &fakeAttestor{want: ExpectedChallenge(&NativeDeviceRegisterRequest{PairingToken: token}), result: attest.Result{Level: "strongbox", BootState: "locked-verified", Serials: []string{"1", "2"}}}
	engine.SetAttestor(fa)
	_, pub := signingKey(t)
	dev, err := engine.RegisterNativeDevice(&NativeDeviceRegisterRequest{PairingToken: token, DeviceName: "p", DeviceIdentifier: "i", PublicKey: pub, PushToken: "fcm", Attestation: []string{base64.StdEncoding.EncodeToString([]byte("cert"))}})
	if err != nil {
		t.Fatal(err)
	}
	if fa.calls != 1 || dev.AttestedLevel != "strongbox" || dev.BootState != "locked-verified" || dev.AttestedAt == nil {
		t.Fatalf("%+v calls=%d", dev, fa.calls)
	}
	stored, _ := dbStore.GetNativeDevice(dev.ID)
	if stored.AttestedLevel != "strongbox" || len(stored.AttestationSerials) != 2 {
		t.Fatalf("stored %+v", stored)
	}
}

func TestRegisterNativeDeviceWithoutAttestationIsNone(t *testing.T) {
	engine, _, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	token, _, _, _ := engine.GenerateDevicePairingToken(user.ID, true)
	fa := &fakeAttestor{}
	engine.SetAttestor(fa)
	_, pub := signingKey(t)
	dev, err := engine.RegisterNativeDevice(&NativeDeviceRegisterRequest{PairingToken: token, DeviceName: "p", DeviceIdentifier: "i", PublicKey: pub, PushToken: "fcm"})
	if err != nil || dev.AttestedLevel != "none" || fa.calls != 0 {
		t.Fatalf("%v %+v calls=%d", err, dev, fa.calls)
	}
}

func TestRegisterNativeDeviceBadChainStillPairs(t *testing.T) {
	engine, _, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	token, _, _, _ := engine.GenerateDevicePairingToken(user.ID, true)
	engine.SetAttestor(&fakeAttestor{want: []byte("other"), result: attest.Result{Level: "tee"}})
	_, pub := signingKey(t)
	dev, err := engine.RegisterNativeDevice(&NativeDeviceRegisterRequest{PairingToken: token, DeviceName: "p", DeviceIdentifier: "i", PublicKey: pub, PushToken: "fcm", Attestation: []string{"!!not base64!!"}})
	if err != nil || dev.AttestedLevel != "none" {
		t.Fatalf("%v %+v", err, dev)
	}
}
```

`internal/api/device_attestation_test.go`:

```go
func TestRegisterHandlerReturnsAttestedLevelAndCapsBody(t *testing.T) {
	server, _, _, mfaEngine, _, cleanup := setupTestServer(t)
	defer cleanup()
	// happy path through the mux with a fake attestor installed via mfaEngine.SetAttestor: body includes
	// "device":{"attestedLevel":"tee","bootState":"locked-verified"}.
	// oversize: a body of 70 KiB → 400 and no device created (assert via the register error/JSON).
}
```

Write the two cases in full following `TestTokenEndpointDeviceSignOnGrant`'s style (real HTTP through `server.httpServer.Handler`); no comment placeholders may remain.

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/mfa/ ./internal/api/ -run 'Challenge|Attest' -count=1`
Expected: FAIL (undefined).

- [ ] **Step 3: Implement**

`config.go`: add fields and loading:

```go
	AttestationExtraRoots string   // KYIDENTITY_ATTESTATION_EXTRA_ROOTS, PEM file path, optional
	AttestationStatusURL  string   // KYIDENTITY_ATTESTATION_STATUS_URL, "" disables
	KyAuthCertSHA256      []string // KYIDENTITY_KYAUTH_CERT_SHA256, comma-separated lowercase hex
```

```go
	cfg.AttestationExtraRoots = strings.TrimSpace(os.Getenv("KYIDENTITY_ATTESTATION_EXTRA_ROOTS"))
	if v, ok := os.LookupEnv("KYIDENTITY_ATTESTATION_STATUS_URL"); ok {
		cfg.AttestationStatusURL = strings.TrimSpace(v)
	} else {
		cfg.AttestationStatusURL = "https://android.googleapis.com/attestation/status"
	}
	if cfg.AttestationStatusURL != "" && !strings.HasPrefix(cfg.AttestationStatusURL, "https://") {
		return nil, errors.New("KYIDENTITY_ATTESTATION_STATUS_URL must be https")
	}
	cfg.KyAuthCertSHA256 = []string{"52f61684029401fcb0137b334ad41907f83948fa1ec1377834f3b4291765fd7b"}
	if v := strings.TrimSpace(os.Getenv("KYIDENTITY_KYAUTH_CERT_SHA256")); v != "" {
		cfg.KyAuthCertSHA256 = nil
		for _, d := range strings.Split(v, ",") {
			d = strings.ToLower(strings.TrimSpace(d))
			if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(d) {
				return nil, fmt.Errorf("KYIDENTITY_KYAUTH_CERT_SHA256: %q is not a 64-hex digest", d)
			}
			cfg.KyAuthCertSHA256 = append(cfg.KyAuthCertSHA256, d)
		}
	}
```

`internal/attest/verifier.go` (new, small):

```go
type Verifier struct {
	roots         Roots
	status        Status
	appPackage    string
	digests       [][]byte
	requireLocked func() bool
}

func NewVerifier(roots Roots, status Status, appPackage string, digests [][]byte, requireLocked func() bool) *Verifier {
	return &Verifier{roots, status, appPackage, digests, requireLocked}
}

func (v *Verifier) Verify(chain [][]byte, want Expectation) Result {
	want.AppPackage, want.AppDigests, want.RequireLockedBootloader = v.appPackage, v.digests, v.requireLocked()
	if want.Now.IsZero() {
		want.Now = time.Now()
	}
	return Verify(chain, want, v.roots, v.status)
}
```

`mfa.go`:

```go
type Attestor interface {
	Verify(chain [][]byte, want attest.Expectation) attest.Result
}

// SetAttestor installs the chain verifier; nil grades every registration none.
func (e *Engine) SetAttestor(a Attestor) { e.attestor = a }

func ExpectedChallenge(req *NativeDeviceRegisterRequest) []byte {
	cred := req.PairingToken
	if cred == "" {
		cred = req.UserID + "|" + req.PINCode
	}
	sum := sha256.Sum256([]byte("kyidentity-attest-v1|" + cred))
	return sum[:]
}
```

Add `Attestation []string \`json:"attestation,omitempty"\`` to the request struct. In `RegisterNativeDevice`, after `RegisterNativeDeviceWithPairingToken` succeeds and before `return device, nil`:

```go
	device.AttestedLevel, device.BootState = "none", "unknown"
	if len(req.Attestation) > 0 && e.attestor != nil {
		chain := make([][]byte, 0, len(req.Attestation))
		for _, b64 := range req.Attestation {
			der, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				chain = nil
				break
			}
			chain = append(chain, der)
		}
		spki, _ := crypto.P256SPKI(req.PublicKey) // add to crypto: returns the DER SPKI for either accepted input form
		res := e.attestor.Verify(chain, attest.Expectation{Challenge: ExpectedChallenge(req), PublicKeySPKI: spki})
		device.AttestedLevel, device.BootState, device.AttestationReason = res.Level, res.BootState, res.Reason
		now := time.Now().UTC()
		if err := e.store.SetNativeDeviceAttestation(device.ID, res.Level, res.BootState, res.Serials, now); err != nil {
			return nil, err
		}
		if res.Level != "none" {
			device.AttestedAt = &now
		}
	}
```

`AttestationReason` is a transient field on `NativeDevice` (`json:"-"`) for the audit row; add it to the model. `crypto.P256SPKI(encoded string) ([]byte, error)`: parse via `ParseP256PublicKey`, then `x509.MarshalPKIXPublicKey`. Note the empty-`attestation` case is handled before the store call so an old client's registration path is byte-identical.

`device_handlers.go` `RegisterNativeDevice`: wrap the body with `http.MaxBytesReader(w, r.Body, 64*1024)`; add `"attestedLevel": dev.AttestedLevel, "bootState": dev.BootState, "attestationReason": dev.AttestationReason` to the audit details.

`main.go`: after config load:

```go
	embedded, err := attest.LoadEmbeddedRoots()
	// fatal on error
	extra, err := attest.LoadExtraRoots(cfg.AttestationExtraRoots)
	// fatal on error
	_, base := embedded.Pool()
	roots := attest.NewRefreshingRoots(append(base, extra...), "https://android.googleapis.com/attestation/root", httpFetch)
	status := attest.NewStatusList(cfg.AttestationStatusURL, httpFetch)
	if cfg.AttestationStatusURL == "" {
		logger.Warn("attestation revocation check disabled: KYIDENTITY_ATTESTATION_STATUS_URL is empty")
	}
	digests := make([][]byte, 0, len(cfg.KyAuthCertSHA256))
	for _, d := range cfg.KyAuthCertSHA256 { b, _ := hex.DecodeString(d); digests = append(digests, b) }
	mfaEngine.SetAttestor(attest.NewVerifier(roots, status, "org.kysecurity.authenticator", digests, func() bool {
		s, _ := dbStore.AttestationSettings()
		return s.RequireLockedBootloader
	}))
```

with `httpFetch` a 10-second-timeout `http.Client` GET returning body (cap 4 MiB), header, error. `AttestationSettings()` is defined in Task 6; until then implement it in this task as a store method returning the default (Task 6 replaces the body). Refresh both caches once at startup in a goroutine (errors logged, not fatal) and in the housekeeping (Task 7).

- [ ] **Step 4: Run tests**

Run: `gofmt -l . && go vet ./... && go test -race -count=1 ./internal/mfa/ ./internal/api/ ./internal/config/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config internal/mfa internal/api internal/attest internal/crypto internal/store cmd
git commit -m "feat(mfa): verify device attestation at registration and record the level"
```

---

### Task 5: The grant honours the attested level

**Files:**
- Modify: `internal/oauth/device_assertion.go` (evidence ~287-296, binding ~332, re-check ~334, claims ~364-368)
- Test: `internal/oauth/device_assertion_test.go`

- [ ] **Step 1: Write the failing tests**

Extend the fixture: `newSignOnFixture` keeps `UpsertNativeDevice`; add a helper `f.attest(t, level string)` that calls `f.db.SetNativeDeviceAttestation("dev-1", level, "locked-verified", []string{"1"}, time.Now())`.

```go
func TestAttestedDeviceSatisfiesMandatoryMFA(t *testing.T) {
	f := newSignOnFixture(t)
	f.requireOrganizationMFA(t, []string{"push"}, 0) // MFA required, push allowed, no grace
	f.attest(t, "tee")
	resp, _, err := f.engine.ExchangeDeviceAssertion(signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil)), f.client.ID, "127.0.0.1", "t")
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := f.engine.keyManager.VerifyJWT(resp.IDToken)
	amr, _ := claims["amr"].([]any)
	if len(amr) != 3 || amr[0] != "hwk" || amr[1] != "user" || amr[2] != "mfa" || claims["acr"] != "urn:kysignon:acr:mfa" || claims["attested"] != "tee" {
		t.Fatalf("claims %v", claims)
	}
}

func TestUnattestedDeviceStillRefusedUnderMandatoryMFA(t *testing.T) {
	f := newSignOnFixture(t)
	f.requireOrganizationMFA(t, []string{"push"}, 0)
	_, _, err := f.engine.ExchangeDeviceAssertion(signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil)), f.client.ID, "127.0.0.1", "t")
	if !errors.Is(err, ErrDeviceSignOnNotPermitted) {
		t.Fatalf("want not permitted, got %v", err)
	}
}

func TestAttestedDeviceAllowsFreshPasswordPolicy(t *testing.T) {
	// set the client's app policy to Mode fresh / Factor password (reuse the helper from
	// TestExchangeDeviceAssertionPasswordPolicyModes); attest tee; assert issued.
}

func TestDowngradeDuringExchangeRefuses(t *testing.T) {
	f := newSignOnFixture(t)
	f.attest(t, "strongbox")
	beforeDeviceTokenRecord = func() { f.attest(t, "none") }
	defer func() { beforeDeviceTokenRecord = func() {} }()
	_, _, err := f.engine.ExchangeDeviceAssertion(signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil)), f.client.ID, "127.0.0.1", "t")
	if !errors.Is(err, ErrDeviceSignOnDisabled) && !errors.Is(err, ErrDeviceSignOnNotPermitted) {
		t.Fatalf("downgrade mid-exchange must refuse, got %v", err)
	}
	// no session, no issued token (reuse the fixture's counting helpers)
}
```

Fill the two bodies marked by comments with real code following the neighbouring tests; no comment placeholders may remain. Update every existing assertion on `amr == ["pop"]` to run against an unattested device (the fixture default), so they keep passing.

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/oauth/ -run 'Attested|Downgrade' -count=1`
Expected: FAIL.

- [ ] **Step 3: Implement**

Replace the evidence block:

```go
	attested := dev.AttestedLevel == "tee" || dev.AttestedLevel == "strongbox"
	evidence := store.AuthenticationEvidence{PrimaryAuthenticatedAt: &now}
	if attested {
		// Hardware possession plus hardware-enforced per-use user verification, proven by the
		// attestation chain at pairing: two factors. The push-approver factor bit is this same key.
		evidence.FactorAuthenticatedAt, evidence.FactorMethod = &now, "push"
	}
	policy, binding, err := e.store.ClientAuthenticationPolicyBinding(clientID)
	...
	modeOK := attested || policy.Mode == "reuse"
	if !policy.Valid() || !modeOK || policy.EvidenceReason(evidence, now) != "" {
		return nil, who, errAppPolicy
	}
```

Binding: `Device: store.DeviceBinding{ID: dev.ID, UserID: dev.UserID, PublicKey: dev.PublicKey, AttestedLevel: dev.AttestedLevel}`. Re-check after `ErrAppAccessDenied`: add `|| cur.AttestedLevel != dev.AttestedLevel` to the disabled branch.

Claims:

```go
	if attested {
		claims["amr"] = []string{"hwk", "user", "mfa"}
		claims["acr"] = "urn:kysignon:acr:mfa"
		claims["attested"] = dev.AttestedLevel
	} else {
		claims["amr"] = []string{"pop"}
		claims["acr"] = DeviceACR
	}
```

- [ ] **Step 4: Run tests**

Run: `go test -race -count=1 ./internal/oauth/ ./internal/api/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/oauth internal/api
git commit -m "feat(oauth): attested devices earn MFA grade in device sign-on"
```

---

### Task 6: Locked-bootloader admin setting

**Files:**
- Create: `internal/store/attestation_settings.go`
- Create: `internal/api/attestation_settings_handlers.go`
- Modify: `internal/api/server.go` (routes next to the alerts settings routes ~282)
- Modify: `web/src/types.ts`, `web/src/parsers.ts`, `web/src/components/AdminEnrollmentPolicies.tsx` (a "Device sign-on" card with one switch)
- Test: `internal/store/store_test.go`, `internal/api/attestation_settings_test.go`, `web/src/parsers.test.ts`

**Interfaces:**
- Produces: `type AttestationSettings struct { RequireLockedBootloader bool \`json:"requireLockedBootloader"\` }`; `func (s *Store) AttestationSettings() (AttestationSettings, error)` (default false on `ErrNotFound`); `func (s *Store) SetAttestationSettings(a AttestationSettings, audit *AuditEvent) error`; `GET /api/admin/attestation/settings` (permRead) and `PUT` (permAdmin, step-up) mirroring `alert_handlers.go`; audit `admin.attestation_configured`.

- [ ] **Step 1: Failing tests**

Store: round trip default → set true → read true. Handler: GET returns `{"requireLockedBootloader":false}`; PUT with step-up flips it and writes the audit action; PUT without step-up is refused the same way the alerts PUT is (copy that test's setup). Web: `parseAttestationSettings` accepts `{requireLockedBootloader:true}` and rejects a non-boolean.

- [ ] **Step 2: Implement** by copying `store/alerts.go` `AlertSettings`/`SetAlertSettings` (key `attestation`) and `api/alert_handlers.go` `GetSettings`/`PutSettings` (`h.audit.Prepare("admin.attestation_configured", ...)`, `event.Committed()`), registering the two routes with the same permission and step-up flags as the alerts routes. Web: add `AttestationSettings` type, `parseAttestationSettings`, and in `AdminEnrollmentPolicies.tsx` a card "Device sign-on" with a checkbox "Require a locked bootloader for MFA-grade device sign-on" that loads via `apiJson('/api/admin/attestation/settings', parseAttestationSettings)` and saves via `requestGrant('Change device attestation policy.', 'PUT /api/admin/attestation/settings')` then `apiJson(..., {method:'PUT', stepUpToken, body: JSON.stringify(next)})`, plus one line of help text: "Off: the bootloader state is recorded but not enforced. On: new pairings and the daily sweep refuse MFA grade for unlocked bootloaders."

- [ ] **Step 3: Verify** `go test ./internal/store/ ./internal/api/ -run 'Attestation' -count=1` and `cd web && npm run build && npm test`; commit `feat(admin): locked-bootloader setting for device attestation` (include the rebuilt `web/dist`).

---

### Task 7: Daily sweep and caches refresh

**Files:**
- Create: `internal/mfa/attestation_sweep.go`
- Modify: `cmd/kyidentity/main.go` (housekeep closure ~163-180: run the sweep when 24 h have passed since the last run, tracked in a local variable; also call `roots.Refresh()` and `status.Refresh()` then)
- Test: `internal/mfa/attestation_sweep_test.go`

**Interfaces:**
- Produces: `func (e *Engine) SweepAttestations(status attest.Status, requireLocked bool, audit func(deviceID, userID, reason string)) (downgraded int, err error)`.

- [ ] **Step 1: Failing test**

```go
func TestSweepDowngradesRevokedAndUnlocked(t *testing.T) {
	engine, dbStore, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()
	mk := func(id, boot string, serials []string) {
		dev := &store.NativeDevice{ID: id, UserID: user.ID, DeviceName: id, DeviceIdentifier: id, PublicKey: "pk", IsMFAApprover: true, CanSignOn: true}
		if err := dbStore.UpsertNativeDevice(dev); err != nil {
			t.Fatal(err)
		}
		if err := dbStore.SetNativeDeviceAttestation(id, "tee", boot, serials, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	mk("ok", "locked-verified", []string{"aa"})
	mk("revoked", "locked-verified", []string{"bb"})
	mk("unlocked", "unlocked", []string{"cc"})
	var reasons []string
	n, err := engine.SweepAttestations(staticStatus{"bb": true}, true, func(id, uid, reason string) { reasons = append(reasons, id+":"+reason) })
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	for id, want := range map[string]string{"ok": "tee", "revoked": "none", "unlocked": "none"} {
		if d, _ := dbStore.GetNativeDevice(id); d.AttestedLevel != want {
			t.Fatalf("%s: %s", id, d.AttestedLevel)
		}
	}
	if len(reasons) != 2 {
		t.Fatalf("reasons %v", reasons)
	}
	// status unknown: nothing is downgraded (fail safe for the sweep; registration is the strict path)
	n, _ = engine.SweepAttestations(unknownStatus{}, false, func(string, string, string) {})
	if n != 0 {
		t.Fatal("unknown status must not downgrade")
	}
}
```

(`staticStatus`/`unknownStatus` are copied into this package's tests.)

- [ ] **Step 2: Implement**

```go
func (e *Engine) SweepAttestations(status attest.Status, requireLocked bool, audit func(deviceID, userID, reason string)) (int, error) {
	devices, err := e.store.ListAttestedDevices()
	if err != nil {
		return 0, err
	}
	downgraded := 0
	for _, d := range devices {
		reason := ""
		for _, s := range d.AttestationSerials {
			revoked, known := status.Revoked(s)
			if known && revoked {
				reason = "certificate " + s + " revoked"
				break
			}
		}
		if reason == "" && requireLocked && d.BootState != "locked-verified" && d.BootState != "locked-selfsigned" {
			reason = "bootloader not locked (" + d.BootState + ")"
		}
		if reason == "" {
			continue
		}
		if err := e.store.SetNativeDeviceAttestation(d.ID, "none", d.BootState, d.AttestationSerials, time.Now()); err != nil {
			return downgraded, err
		}
		audit(d.ID, d.UserID, reason)
		downgraded++
	}
	return downgraded, nil
}
```

`main.go` housekeep: keep `lastSweep time.Time`; when `time.Since(lastSweep) >= 24h`: `_ = roots.Refresh(); _ = status.Refresh(); s, _ := dbStore.AttestationSettings(); n, err := mfaEngine.SweepAttestations(status, s.RequireLockedBootloader, func(id, uid, reason string) { _ = auditLogger.Record("device.attestation_downgraded", "", "", id, "device", "", "sweep", "success", map[string]any{"userId": uid, "reason": reason}) })`; log n/err; set `lastSweep`.

- [ ] **Step 3: Verify and commit** `go test -race ./internal/mfa/ -count=1`; `git commit -m "feat(mfa): daily attestation sweep"`.

---

### Task 8: Devices page badge, docs

**Files:**
- Modify: `web/src/types.ts` (`NativeDevice` gains `attestedLevel: 'none'|'tee'|'strongbox'`, `bootState: string`), `web/src/parsers.ts` (`parseDevice`), `web/src/components/DeviceSettings.tsx` (device card ~431-467), `web/src/parsers.test.ts`
- Modify: `AGENTS.md`, `README.md`
- Modify: `docs` of the spec in kyauth-android only if a contract changed during implementation (record in the report)

- [ ] **Step 1: Web**

In the device card's `.device-status` add, before the sign-on checkbox:

```tsx
{dev.attestedLevel === 'strongbox' && <span className="badge-type"><ShieldCheck size={12} /> Attested: StrongBox</span>}
{dev.attestedLevel === 'tee' && <span className="badge-type"><ShieldCheck size={12} /> Attested: TEE</span>}
{dev.attestedLevel === 'none' && <span className="text-muted text-sm">Not attested. Pair KyAuth again to attest this phone.</span>}
{dev.bootState === 'unlocked' && <span className="text-muted text-sm">Bootloader unlocked.</span>}
```

(`ShieldCheck` from `lucide-react`, which the file already imports icons from.) Parser: `attestedLevel: oneOf(o, 'attestedLevel', ['none','tee','strongbox'], 'none')` using whatever enum helper `parsers.ts` has (add a small one if none), `bootState: str(o, 'bootState', 'unknown')`. Test: `parseDevice` round-trips both and defaults them.

- [ ] **Step 2: Docs**

AGENTS.md (Security Invariants, device grant bullets): registration verifies `attestation` (chain, leaf first) through `internal/attest` against Google's roots (+ `KYIDENTITY_ATTESTATION_EXTRA_ROOTS`), the status list (`KYIDENTITY_ATTESTATION_STATUS_URL`), the challenge `SHA-256("kyidentity-attest-v1|"+credential)`, the hardware-enforced per-use policy and KyAuth's package + digest (`KYIDENTITY_KYAUTH_CERT_SHA256`); grades `none|tee|strongbox`; only attested devices earn MFA grade (`amr [hwk,user,mfa]`, `acr mfa`, claim `attested`); `none` keeps single-factor; `DeviceBinding` includes the level; admin setting `attestation.requireLockedBootloader` (default off; recorded either way; enforced at pairing and by the daily sweep); sweep `device.attestation_downgraded`; the emulator/physical-device caveat. README: the three env vars, the setting, the two audit actions, the `attested` claim. Replace the earlier follow-up bullet.

- [ ] **Step 3: Verify everything and commit**

Run: `gofmt -l . && go vet ./... && go test -race -count=1 -timeout 20m ./... && (cd web && npm run build && npm test)`
Expected: all green.

```bash
git add web/src web/dist AGENTS.md README.md
git commit -m "feat(web): attestation badge on the devices page; docs"
```
