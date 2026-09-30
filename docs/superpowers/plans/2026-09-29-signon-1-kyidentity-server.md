# KyIdentity device sign-on grant Implementation Plan (1 of 4)

> Superseded by audit P1 (2026-09-30): amr is [pop], acr urn:kysignon:acr:device, single-factor.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** KyIdentity lets a paired native device with the sign-on capability redeem an ES256 assertion for an ID token whose audience is a registered client.

**Architecture:** A `can_sign_on` flag on `native_devices`, granted from the pairing-token row and toggled per device. A new RFC 7523 JWT-bearer branch on `POST /oauth/token` verifies the assertion against that one device's public key, spends the `jti` durably, opens a short device login session, and mints tokens through the existing `RecordIssuedToken` / `EnsureClientSession` / `identityClaims` path.

**Tech Stack:** Go, `modernc.org/sqlite`, stdlib `crypto/ecdsa`, existing `internal/crypto.JWTKeyManager` (RS256). No new dependency.

**Spec:** `kyauth-android/docs/superpowers/specs/2026-09-29-kyidentity-account-manager-signon-design.md`, section 1.

**Repo:** `/home/yoshi/git/busnes.app/KyIdentity-server`. Branch from `main`: `feature/device-signon-grant`.

## Global Constraints

- Assertion header must be exactly `alg=ES256`, `typ=JWT`, `kid=<device_id>`; claims `iss=device:<device_id>`, `sub=<user_id>`, `aud=<issuerURL>/oauth/token`, `client_id`, `iat`, `exp` ≤ `iat`+300, `jti`.
- Verify against the named device's key only; never loop over the user's devices.
- Clock skew allowance is 60 seconds.
- Rate limit bucket `device_signon`, 10 burst, 0.2/s.
- No refresh token. Access and ID tokens keep `AccessTokenTTL` (15 min).
- Audit `device.signon` success and failure with `deviceId` and `clientId`; never log the assertion.
- The `client_id` form field must equal the assertion's `client_id` claim.
- Error responses to the caller are `invalid_grant` with a generic description; the precise reason goes to audit (matches `Token`'s existing convention).
- CI: `gofmt -l .`, `go vet ./...`, `go test -race -count=1 -timeout 20m ./...`.

## Review Focus

1. A device whose row was deleted between assertion build and redeem → `invalid_grant`, not a nil dereference. Pinned in Task 5 (`TestExchangeDeviceAssertionUnknownDevice`).
2. An assertion with `exp` more than 300 s after `iat` (attacker-chosen long window) → refused even if not yet expired. Pinned in Task 5 (`TestExchangeDeviceAssertionWindowTooLong`).
3. A signature that is 64 bytes but not on the curve, or 70 bytes DER, → refused without panic. Pinned in Task 4 (`TestVerifyES256RejectsDERAndGarbage`).
4. A user disabled by SCIM (`status != active`) after pairing → `RecordIssuedToken` refuses; the grant must surface `invalid_grant`, not 500. Pinned in Task 5 (`TestExchangeDeviceAssertionInactiveUser`).
5. A pairing token generated before this change (no `sign_on` column value) → registers a device with `can_sign_on = 0`. Pinned in Task 1 (migration test) and Task 2.

---

### Task 1: Schema, models and column lists

**Files:**
- Modify: `internal/store/store.go` (DDL ~128-153, `migrate()` chain ~328-413, `CreateDevicePairingToken` 1238, `devicePairingTokenColumns` 1245, `scanDevicePairingToken` 1247, `RegisterNativeDeviceWithPairingToken` insert 1335, `ListUserNativeDevices` 1386, `GetNativeDevice` 1414, `migrateLegacyDevicePairingTokens` 561)
- Modify: `internal/store/models.go` (`NativeDevice` 94, `DevicePairingToken` 108)
- Modify: `internal/store/restore.go:38` only if `device_signon_jtis` should be cleared on restore (it should: add it to `restoredCleared`).
- Test: `internal/store/store_test.go`

**Interfaces:**
- Produces: `NativeDevice.CanSignOn bool` (json `canSignOn`), `DevicePairingToken.SignOn bool`, table `device_signon_jtis(jti TEXT PRIMARY KEY, expires_at DATETIME NOT NULL)`.

- [ ] **Step 1: Write the failing migration test**

Append to `internal/store/store_test.go`, next to `TestNativeDevicePushTokenReplayStateMigrates` (line 193), copying its legacy-table setup:

```go
func TestDeviceSignOnColumnsMigrate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`CREATE TABLE users (id TEXT PRIMARY KEY);
		CREATE TABLE native_devices (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		device_name TEXT NOT NULL, device_identifier TEXT NOT NULL, platform TEXT NOT NULL DEFAULT 'android',
		public_key TEXT, push_token TEXT, push_token_updated_at_ms INTEGER NOT NULL DEFAULT 0,
		is_mfa_approver BOOLEAN NOT NULL DEFAULT 0, last_seen_at DATETIME, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(user_id, device_identifier));
		CREATE TABLE device_pairing_tokens (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token_hash TEXT NOT NULL UNIQUE, pin_hash TEXT NOT NULL, expires_at DATETIME NOT NULL, used_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
		INSERT INTO users(id) VALUES ('u1');
		INSERT INTO native_devices(id,user_id,device_name,device_identifier) VALUES ('d1','u1','old phone','ident-1');`); err != nil {
		t.Fatal(err)
	}
	legacy.Close()

	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for table, col := range map[string]string{"native_devices": "can_sign_on", "device_pairing_tokens": "sign_on"} {
		var n int
		if err := s.db.QueryRow(`SELECT count(*) FROM pragma_table_info(?) WHERE name = ?`, table, col).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("%s.%s missing after migration", table, col)
		}
	}
	dev, err := s.GetNativeDevice("d1")
	if err != nil || dev == nil {
		t.Fatalf("GetNativeDevice: %v %v", dev, err)
	}
	if dev.CanSignOn {
		t.Fatal("a pre-existing device must not gain sign-on by migration")
	}
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='device_signon_jtis'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("device_signon_jtis table missing: %d %v", n, err)
	}
}
```

Check the imports at the top of `store_test.go` already include `database/sql` and `path/filepath` (they do for the replay-state test); add them if not.

- [ ] **Step 2: Run it to verify it fails**

Run: `cd /home/yoshi/git/busnes.app/KyIdentity-server && go test ./internal/store/ -run TestDeviceSignOnColumnsMigrate -count=1`
Expected: FAIL, `dev.CanSignOn undefined` compile error.

- [ ] **Step 3: Add the model fields**

In `internal/store/models.go`:

```go
type NativeDevice struct {
	ID                   string     `json:"id"`
	UserID               string     `json:"userId"`
	DeviceName           string     `json:"deviceName"`
	DeviceIdentifier     string     `json:"deviceIdentifier"`
	Platform             string     `json:"platform"`
	PublicKey            string     `json:"publicKey,omitempty"`
	PushToken            string     `json:"pushToken,omitempty"`
	PushTokenUpdatedAtMS int64      `json:"-"`
	IsMFAApprover        bool       `json:"isMfaApprover"`
	CanSignOn            bool       `json:"canSignOn"`
	LastSeenAt           *time.Time `json:"lastSeenAt,omitempty"`
	CreatedAt            time.Time  `json:"createdAt"`
}

type DevicePairingToken struct {
	ID        string     `json:"id"`
	UserID    string     `json:"userId"`
	TokenHash string     `json:"-"`
	PINHash   string     `json:"-"`
	SignOn    bool       `json:"signOn"`
	ExpiresAt time.Time  `json:"expiresAt"`
	UsedAt    *time.Time `json:"usedAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}
```

- [ ] **Step 4: DDL and migrations**

In `internal/store/store.go`, in the `CREATE TABLE IF NOT EXISTS native_devices` DDL add `can_sign_on BOOLEAN NOT NULL DEFAULT 0,` after `is_mfa_approver`. In `device_pairing_tokens` add `sign_on BOOLEAN NOT NULL DEFAULT 0,` after `pin_hash`. Add a new table after `device_pairing_tokens`:

```sql
	CREATE TABLE IF NOT EXISTS device_signon_jtis (
		jti TEXT PRIMARY KEY,
		expires_at DATETIME NOT NULL
	);
```

Add two migration functions modelled on `migrateNativeDevicePushTokenReplayState` (store.go:531), and call them from the `migrate()` chain right after it:

```go
func (s *Store) migrateNativeDeviceCanSignOn() error {
	return s.addColumnIfMissing("native_devices", "can_sign_on", `ALTER TABLE native_devices ADD COLUMN can_sign_on BOOLEAN NOT NULL DEFAULT 0`)
}

func (s *Store) migrateDevicePairingTokenSignOn() error {
	return s.addColumnIfMissing("device_pairing_tokens", "sign_on", `ALTER TABLE device_pairing_tokens ADD COLUMN sign_on BOOLEAN NOT NULL DEFAULT 0`)
}

// addColumnIfMissing runs alter unless table already has column.
func (s *Store) addColumnIfMissing(table, column, alter string) error {
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM pragma_table_info(?) WHERE name = ?`, table, column).Scan(&n); err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	_, err := s.db.Exec(alter)
	return err
}
```

In `migrate()`:

```go
	if err := s.migrateNativeDeviceCanSignOn(); err != nil {
		return err
	}
	if err := s.migrateDevicePairingTokenSignOn(); err != nil {
		return err
	}
```

Read `migrateLegacyDevicePairingTokens` (store.go:561). Its `CREATE` statement lists every column; add `sign_on BOOLEAN NOT NULL DEFAULT 0` to it so a rebuilt table matches the DDL. Then in `internal/store/restore.go` add `"device_signon_jtis"` to `restoredCleared`.

- [ ] **Step 5: Column lists**

`CreateDevicePairingToken`:

```go
	query := `INSERT INTO device_pairing_tokens (id, user_id, token_hash, pin_hash, sign_on, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
	token.CreatedAt = time.Now().UTC()
	_, err := s.db.Exec(query, token.ID, token.UserID, token.TokenHash, token.PINHash, token.SignOn, token.ExpiresAt, token.CreatedAt)
```

```go
const devicePairingTokenColumns = `id, user_id, token_hash, pin_hash, sign_on, expires_at, used_at, created_at`

func scanDevicePairingToken(row *sql.Row) (*DevicePairingToken, error) {
	t := &DevicePairingToken{}
	err := row.Scan(&t.ID, &t.UserID, &t.TokenHash, &t.PINHash, &t.SignOn, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt)
```

`RegisterNativeDeviceWithPairingToken` insert (line 1335):

```go
		INSERT INTO native_devices (id, user_id, device_name, device_identifier, platform, public_key, push_token, is_mfa_approver, can_sign_on, last_seen_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id, device_identifier) DO UPDATE SET
			device_name = excluded.device_name,
			platform = excluded.platform,
			public_key = excluded.public_key,
			push_token = excluded.push_token,
			is_mfa_approver = excluded.is_mfa_approver,
			can_sign_on = excluded.can_sign_on,
			last_seen_at = excluded.last_seen_at
	`, dev.ID, dev.UserID, dev.DeviceName, dev.DeviceIdentifier, dev.Platform, dev.PublicKey, dev.PushToken, dev.IsMFAApprover, dev.CanSignOn, dev.LastSeenAt, dev.CreatedAt)
```

`ListUserNativeDevices`: select `..., is_mfa_approver, can_sign_on, last_seen_at, created_at` and scan `&dev.IsMFAApprover, &dev.CanSignOn, &dev.LastSeenAt, &dev.CreatedAt`.

`GetNativeDevice`: select `..., push_token_updated_at_ms, is_mfa_approver, can_sign_on, last_seen_at, created_at` and scan `&dev.PushTokenUpdatedAtMS, &dev.IsMFAApprover, &dev.CanSignOn, &dev.LastSeenAt, &dev.CreatedAt`.

`UpsertNativeDevice` (1365): add `can_sign_on` the same way as the register insert.

- [ ] **Step 6: Run the store tests**

Run: `go test ./internal/store/ -count=1`
Expected: PASS including `TestDeviceSignOnColumnsMigrate`.

- [ ] **Step 7: Commit**

```bash
git add internal/store
git commit -m "feat(store): sign-on capability on devices and pairing tokens"
```

---

### Task 2: Pairing-token flag flows into the registered device

**Files:**
- Modify: `internal/mfa/mfa.go` (`GenerateDevicePairingToken` 194, `RegisterNativeDevice` 238-300)
- Modify: `internal/api/device_handlers.go` (`GenerateDevicePairingToken` 39-80)
- Test: `internal/mfa/mfa_test.go`

**Interfaces:**
- Produces: `func (e *Engine) GenerateDevicePairingToken(userID string, signOn bool) (token, pin string, expiresAt time.Time, err error)`. Registration response `device.canSignOn`.

- [ ] **Step 1: Write the failing test**

Append to `internal/mfa/mfa_test.go`:

```go
func TestPairingTokenSignOnFlagReachesDevice(t *testing.T) {
	engine, _, user, cleanup := setupTestMFAEngine(t)
	defer cleanup()

	for _, signOn := range []bool{false, true} {
		token, _, _, err := engine.GenerateDevicePairingToken(user.ID, signOn)
		if err != nil {
			t.Fatal(err)
		}
		_, devicePub := signingKey(t)
		dev, err := engine.RegisterNativeDevice(&NativeDeviceRegisterRequest{
			PairingToken:     token,
			DeviceName:       "phone",
			DeviceIdentifier: fmt.Sprintf("ident-%v", signOn),
			PublicKey:        devicePub,
			PushToken:        "fcm-token",
		})
		if err != nil {
			t.Fatal(err)
		}
		if dev.CanSignOn != signOn {
			t.Fatalf("signOn=%v: device CanSignOn=%v", signOn, dev.CanSignOn)
		}
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/mfa/ -run TestPairingTokenSignOnFlagReachesDevice -count=1`
Expected: FAIL, too many arguments to `GenerateDevicePairingToken`.

- [ ] **Step 3: Implement**

`internal/mfa/mfa.go`:

```go
func (e *Engine) GenerateDevicePairingToken(userID string, signOn bool) (token string, pin string, expiresAt time.Time, err error) {
	...
	item := &store.DevicePairingToken{
		ID:        uuid.New().String(),
		UserID:    userID,
		TokenHash: tokenHash,
		PINHash:   crypto.HashSHA256(pin),
		SignOn:    signOn,
		ExpiresAt: expiresAt,
	}
```

In `RegisterNativeDevice`, where the device struct is built with `IsMFAApprover: true`, add `CanSignOn: validToken.SignOn` (the variable name holding the looked-up `*store.DevicePairingToken` is used for both the token and PIN paths; use whichever name the function already has).

Fix the existing caller in `mfa_test.go:120` (`engine.GenerateDevicePairingToken(user.ID)` → `(user.ID, true)`) and any other caller `grep -rn "GenerateDevicePairingToken(" --include=*.go .` reports.

`internal/api/device_handlers.go` `GenerateDevicePairingToken` handler: decode an optional body before calling the engine. Default is on.

```go
	req := struct {
		SignOn *bool `json:"signOn"`
	}{}
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
	}
	signOn := req.SignOn == nil || *req.SignOn
	token, pin, expiresAt, err := h.mfaEngine.GenerateDevicePairingToken(user.ID, signOn)
```

Add `"signOn": signOn` to the audit details map (currently `nil`) and to the JSON response alongside `pairingToken`.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/mfa/ ./internal/api/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/mfa internal/api/device_handlers.go
git commit -m "feat(pairing): pairing token carries the sign-on grant to the device"
```

---

### Task 3: Per-device sign-on toggle route

**Files:**
- Modify: `internal/store/store.go` (next to `SetNativeDeviceMFAApprover` 1467)
- Modify: `internal/api/device_handlers.go` (after `SetDeviceMFAApprover` 223-251)
- Modify: `internal/api/server.go:164` (route)
- Test: `internal/api/device_signon_test.go` (new)

**Interfaces:**
- Produces: `func (s *Store) SetNativeDeviceCanSignOn(deviceID, userID string, enabled bool) error`; route `PUT /api/notifications/native/devices/{id}/sign-on` body `{"canSignOn": bool}` → `{"success": true}`; 404 when the device is not the caller's.

- [ ] **Step 1: Write the failing test**

Create `internal/api/device_signon_test.go`. Use `setupTestServer(t)` and the session/user helpers the way `push_token_refresh_test.go` does (read its first 60 lines for the exact helper that creates a user with a session cookie and registers a device; reuse those names verbatim):

```go
func TestSetDeviceSignOnTogglesOwnDeviceOnly(t *testing.T) {
	server, dbStore, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	user, cookie := createUserWithSession(t, dbStore) // helper from push_token_refresh_test.go; adapt name
	dev := &store.NativeDevice{ID: "dev-1", UserID: user.ID, DeviceName: "p", DeviceIdentifier: "i", PublicKey: "", CanSignOn: true}
	if err := dbStore.UpsertNativeDevice(dev); err != nil {
		t.Fatal(err)
	}

	do := func(id string, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/api/notifications/native/devices/"+id+"/sign-on", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		server.httpServer.Handler.ServeHTTP(rec, req)
		return rec
	}
	if rec := do("dev-1", `{"canSignOn":false}`); rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	got, _ := dbStore.GetNativeDevice("dev-1")
	if got.CanSignOn {
		t.Fatal("toggle off did not persist")
	}
	other, _ := createUserWithSession(t, dbStore)
	otherDev := &store.NativeDevice{ID: "dev-2", UserID: other.ID, DeviceName: "q", DeviceIdentifier: "j", CanSignOn: false}
	if err := dbStore.UpsertNativeDevice(otherDev); err != nil {
		t.Fatal(err)
	}
	if rec := do("dev-2", `{"canSignOn":true}`); rec.Code != http.StatusNotFound {
		t.Fatalf("foreign device: status %d", rec.Code)
	}
	got, _ = dbStore.GetNativeDevice("dev-2")
	if got.CanSignOn {
		t.Fatal("foreign toggle changed the row")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/api/ -run TestSetDeviceSignOnTogglesOwnDeviceOnly -count=1`
Expected: FAIL with 404/405 from the router (route missing) or a compile error on `CanSignOn` if Task 1 was skipped.

- [ ] **Step 3: Implement store method**

```go
// SetNativeDeviceCanSignOn is not an enrollment change, so it needs none of
// changeEnrollmentDevice's compliance checks.
func (s *Store) SetNativeDeviceCanSignOn(deviceID, userID string, enabled bool) error {
	res, err := s.db.Exec(`UPDATE native_devices SET can_sign_on = ? WHERE id = ? AND user_id = ?`, enabled, deviceID, userID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
```

- [ ] **Step 4: Implement handler and route**

`internal/api/device_handlers.go`:

```go
func (h *DeviceHandler) SetDeviceSignOn(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	deviceID := r.PathValue("id")
	var req struct {
		CanSignOn bool `json:"canSignOn"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	err := h.store.SetNativeDeviceCanSignOn(deviceID, user.ID, req.CanSignOn)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	h.audit.Record("device.sign_on_changed", user.ID, user.Username, deviceID, "device", h.middleware.ClientIP(r), r.UserAgent(), outcome, map[string]any{"canSignOn": req.CanSignOn})
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}
```

Add `"database/sql"` to the imports. `internal/api/server.go` after line 164:

```go
	mux.Handle("PUT /api/notifications/native/devices/{id}/sign-on", authM(http.HandlerFunc(devH.SetDeviceSignOn)))
```

- [ ] **Step 5: Run tests**

Run: `go test ./internal/api/ -run 'TestSetDeviceSignOn' -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/store/store.go internal/api/device_handlers.go internal/api/server.go internal/api/device_signon_test.go
git commit -m "feat(devices): per-device sign-on toggle"
```

---

### Task 4: Parse and verify an ES256 device assertion

**Files:**
- Create: `internal/oauth/device_assertion.go`
- Test: `internal/oauth/device_assertion_test.go`

**Interfaces:**
- Produces:
  - `type deviceAssertion struct { DeviceID, Subject, Audience, ClientID, JTI string; IssuedAt, ExpiresAt int64 }`
  - `func parseDeviceAssertion(compact string) (*deviceAssertion, signingInput []byte, sig []byte, err error)`
  - `func verifyES256(pub *ecdsa.PublicKey, signingInput, sig []byte) bool`
  - `func signDeviceAssertionForTest(t *testing.T, priv *ecdsa.PrivateKey, header map[string]any, claims map[string]any) string` in the test file (used by Task 5 and 6 tests).

- [ ] **Step 1: Write the failing tests**

`internal/oauth/device_assertion_test.go`:

```go
package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
)

func signDeviceAssertionForTest(t *testing.T, priv *ecdsa.PrivateKey, header map[string]any, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func testHeader(kid string) map[string]any {
	return map[string]any{"alg": "ES256", "typ": "JWT", "kid": kid}
}

func testClaims() map[string]any {
	return map[string]any{
		"iss": "device:dev-1", "sub": "user-1", "aud": "https://id.example/oauth/token",
		"client_id": "kypost", "iat": int64(1000), "exp": int64(1200), "jti": "j-1",
	}
}

func TestParseDeviceAssertionRoundTrip(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	compact := signDeviceAssertionForTest(t, priv, testHeader("dev-1"), testClaims())
	a, input, sig, err := parseDeviceAssertion(compact)
	if err != nil {
		t.Fatal(err)
	}
	if a.DeviceID != "dev-1" || a.Subject != "user-1" || a.ClientID != "kypost" || a.JTI != "j-1" || a.IssuedAt != 1000 || a.ExpiresAt != 1200 || a.Audience != "https://id.example/oauth/token" {
		t.Fatalf("claims: %+v", a)
	}
	if !verifyES256(&priv.PublicKey, input, sig) {
		t.Fatal("valid signature refused")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if verifyES256(&other.PublicKey, input, sig) {
		t.Fatal("sibling key accepted")
	}
}

func TestParseDeviceAssertionRejectsBadHeaders(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bad := []map[string]any{
		{"alg": "RS256", "typ": "JWT", "kid": "dev-1"},
		{"alg": "none", "typ": "JWT", "kid": "dev-1"},
		{"alg": "ES256", "typ": "JWT"},
		{"alg": "ES256", "typ": "JWT", "kid": "dev-1", "crit": []string{"x"}},
	}
	for _, h := range bad {
		if _, _, _, err := parseDeviceAssertion(signDeviceAssertionForTest(t, priv, h, testClaims())); err == nil {
			t.Fatalf("header %v accepted", h)
		}
	}
	if _, _, _, err := parseDeviceAssertion("a.b"); err == nil {
		t.Fatal("two segments accepted")
	}
	c := testClaims()
	c["iss"] = "device:other"
	if _, _, _, err := parseDeviceAssertion(signDeviceAssertionForTest(t, priv, testHeader("dev-1"), c)); err == nil {
		t.Fatal("iss/kid mismatch accepted")
	}
}

func TestVerifyES256RejectsDERAndGarbage(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	input := []byte("x.y")
	digest := sha256.Sum256(input)
	der, _ := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if verifyES256(&priv.PublicKey, input, der) {
		t.Fatal("DER signature accepted as raw")
	}
	if verifyES256(&priv.PublicKey, input, make([]byte, 64)) {
		t.Fatal("zero signature accepted")
	}
	n := elliptic.P256().Params().N
	over := make([]byte, 64)
	new(big.Int).Add(n, big.NewInt(1)).FillBytes(over[:32])
	if verifyES256(&priv.PublicKey, input, over) {
		t.Fatal("r >= n accepted")
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/oauth/ -run 'TestParseDeviceAssertion|TestVerifyES256' -count=1`
Expected: FAIL, undefined `parseDeviceAssertion`.

- [ ] **Step 3: Implement**

`internal/oauth/device_assertion.go`:

```go
package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
)

// deviceAssertion is the RFC 7523 assertion a paired KyAuth device signs with its
// enrolled P-256 key to sign in to a suite app. Only the fields the grant checks.
type deviceAssertion struct {
	DeviceID  string
	Subject   string
	Audience  string
	ClientID  string
	JTI       string
	IssuedAt  int64
	ExpiresAt int64
}

const maxAssertionLen = 4096

// parseDeviceAssertion splits a compact JWS and pins the header to exactly what
// KyAuth emits. It verifies nothing about the signature; that needs the device row.
func parseDeviceAssertion(compact string) (*deviceAssertion, []byte, []byte, error) {
	if len(compact) > maxAssertionLen {
		return nil, nil, nil, errors.New("assertion too long")
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, nil, nil, errors.New("assertion is not a compact JWS")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, errors.New("bad header encoding")
	}
	var header map[string]json.RawMessage
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, nil, nil, errors.New("bad header")
	}
	var alg, typ, kid string
	_ = json.Unmarshal(header["alg"], &alg)
	_ = json.Unmarshal(header["typ"], &typ)
	_ = json.Unmarshal(header["kid"], &kid)
	if alg != "ES256" || typ != "JWT" || kid == "" || len(header) != 3 {
		return nil, nil, nil, errors.New("header must be exactly alg=ES256, typ=JWT, kid")
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, errors.New("bad claims encoding")
	}
	var c struct {
		Iss      string `json:"iss"`
		Sub      string `json:"sub"`
		Aud      string `json:"aud"`
		ClientID string `json:"client_id"`
		JTI      string `json:"jti"`
		Iat      int64  `json:"iat"`
		Exp      int64  `json:"exp"`
	}
	if err := json.Unmarshal(claimsJSON, &c); err != nil {
		return nil, nil, nil, errors.New("bad claims")
	}
	if c.Iss != "device:"+kid {
		return nil, nil, nil, errors.New("iss does not name the kid device")
	}
	if c.Sub == "" || c.Aud == "" || c.ClientID == "" || c.JTI == "" || c.Iat == 0 || c.Exp == 0 {
		return nil, nil, nil, errors.New("missing claim")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, errors.New("bad signature encoding")
	}
	a := &deviceAssertion{DeviceID: kid, Subject: c.Sub, Audience: c.Aud, ClientID: c.ClientID, JTI: c.JTI, IssuedAt: c.Iat, ExpiresAt: c.Exp}
	return a, []byte(parts[0] + "." + parts[1]), sig, nil
}

// verifyES256 checks a JWS raw r||s signature over signingInput. DER input is
// refused by length; r and s outside [1, n) are refused before the curve math.
func verifyES256(pub *ecdsa.PublicKey, signingInput, sig []byte) bool {
	if pub == nil || len(sig) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	n := elliptic.P256().Params().N
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return false
	}
	digest := sha256.Sum256(signingInput)
	return ecdsa.Verify(pub, digest[:], r, s)
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/oauth/ -run 'TestParseDeviceAssertion|TestVerifyES256' -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/oauth/device_assertion.go internal/oauth/device_assertion_test.go
git commit -m "feat(oauth): parse and verify ES256 device assertions"
```

---

### Task 5: `ExchangeDeviceAssertion` on the engine

**Files:**
- Modify: `internal/oauth/device_assertion.go`
- Modify: `internal/store/store.go` (new `ConsumeDeviceSignOnJTI`)
- Test: `internal/oauth/device_assertion_test.go`, reusing the engine fixtures `internal/oauth/oauth_test.go` already has (read its top 80 lines for the helper that builds an `Engine` with a store, user and client; reuse those names).

**Interfaces:**
- Produces: `func (e *Engine) ExchangeDeviceAssertion(compact, clientID, ip, userAgent string) (*TokenResponse, string, error)`. The middle return is the device ID for audit (empty when unparseable). Errors are internal detail; the handler maps every error to `invalid_grant`.
- Produces: `func (s *Store) ConsumeDeviceSignOnJTI(jti string, expiresAt time.Time) (bool, error)`; false means already used.

- [ ] **Step 1: Store method and its test**

Append to `internal/store/store_test.go`:

```go
func TestConsumeDeviceSignOnJTIIsSingleUse(t *testing.T) {
	s, cleanup := setupTestStore(t)
	defer cleanup()
	exp := time.Now().UTC().Add(5 * time.Minute)
	ok, err := s.ConsumeDeviceSignOnJTI("j-1", exp)
	if err != nil || !ok {
		t.Fatalf("first use: %v %v", ok, err)
	}
	ok, err = s.ConsumeDeviceSignOnJTI("j-1", exp)
	if err != nil || ok {
		t.Fatalf("replay: %v %v", ok, err)
	}
	// Expired rows are swept so the table cannot grow without bound.
	if _, err := s.db.Exec(`UPDATE device_signon_jtis SET expires_at = ? WHERE jti = 'j-1'`, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	ok, err = s.ConsumeDeviceSignOnJTI("j-2", exp)
	if err != nil || !ok {
		t.Fatal(err)
	}
	var n int
	_ = s.db.QueryRow(`SELECT count(*) FROM device_signon_jtis WHERE jti = 'j-1'`).Scan(&n)
	if n != 0 {
		t.Fatal("expired jti not swept")
	}
}
```

Implement in `store.go`:

```go
// ConsumeDeviceSignOnJTI records a device assertion id once. A second call for the
// same jti returns false. Rows past their expiry are swept on every call; the
// assertion they guard is refused by exp anyway.
func (s *Store) ConsumeDeviceSignOnJTI(jti string, expiresAt time.Time) (bool, error) {
	now := time.Now().UTC()
	if _, err := s.db.Exec(`DELETE FROM device_signon_jtis WHERE expires_at < ?`, now); err != nil {
		return false, err
	}
	res, err := s.db.Exec(`INSERT OR IGNORE INTO device_signon_jtis (jti, expires_at) VALUES (?, ?)`, jti, expiresAt.UTC())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
```

Run: `go test ./internal/store/ -run TestConsumeDeviceSignOnJTI -count=1` → PASS.

- [ ] **Step 2: Write the failing engine tests**

Append to `internal/oauth/device_assertion_test.go`. Use the engine fixture from `oauth_test.go` (it creates a store, a user with `Status: "active"`, an `OAuthClient`, and calls `allowTestAppAccess` from `app_access_test_helpers_test.go`; name it `fx` here and adapt to the real helper names):

```go
type signOnFixture struct {
	engine *Engine
	db     *store.Store
	user   *store.User
	client *store.OAuthClient
	priv   *ecdsa.PrivateKey
	device *store.NativeDevice
}

func newSignOnFixture(t *testing.T) *signOnFixture {
	t.Helper()
	engine, db, user, client := newEngineFixture(t) // existing helper in oauth_test.go; adapt the name
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	dev := &store.NativeDevice{ID: "dev-1", UserID: user.ID, DeviceName: "phone", DeviceIdentifier: "ident-1",
		PublicKey: base64.StdEncoding.EncodeToString(spki), IsMFAApprover: true, CanSignOn: true}
	if err := db.UpsertNativeDevice(dev); err != nil {
		t.Fatal(err)
	}
	return &signOnFixture{engine: engine, db: db, user: user, client: client, priv: priv, device: dev}
}

func (f *signOnFixture) claims(mutate func(map[string]any)) map[string]any {
	now := time.Now().Unix()
	c := map[string]any{
		"iss": "device:dev-1", "sub": f.user.ID, "aud": f.engine.issuerURL + "/oauth/token",
		"client_id": f.client.ID, "iat": now, "exp": now + 120, "jti": uuid.NewString(),
	}
	if mutate != nil {
		mutate(c)
	}
	return c
}

func TestExchangeDeviceAssertionIssuesIDToken(t *testing.T) {
	f := newSignOnFixture(t)
	compact := signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil))
	resp, devID, err := f.engine.ExchangeDeviceAssertion(compact, f.client.ID, "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	if devID != "dev-1" || resp.IDToken == "" || resp.AccessToken == "" {
		t.Fatalf("resp %+v dev %q", resp, devID)
	}
	claims, err := f.engine.keyManager.VerifyJWT(resp.IDToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims["aud"] != f.client.ID || claims["sub"] != f.user.ID || claims["signon_method"] != "device" || claims["device_id"] != "dev-1" || claims["sid"] == "" {
		t.Fatalf("claims %v", claims)
	}
	amr, _ := claims["amr"].([]any)
	if len(amr) == 0 || amr[0] != "hwk" {
		t.Fatalf("amr %v", claims["amr"])
	}
}

func TestExchangeDeviceAssertionRefusals(t *testing.T) {
	f := newSignOnFixture(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cases := map[string]func() (string, string){
		"sibling key":     func() (string, string) { return signDeviceAssertionForTest(t, other, testHeader("dev-1"), f.claims(nil)), f.client.ID },
		"form client_id":  func() (string, string) { return signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil)), "someone-else" },
		"claim client_id": func() (string, string) { return signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(func(c map[string]any) { c["client_id"] = "someone-else" })), "someone-else" },
		"wrong aud":       func() (string, string) { return signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(func(c map[string]any) { c["aud"] = "https://evil/oauth/token" })), f.client.ID },
		"wrong sub":       func() (string, string) { return signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(func(c map[string]any) { c["sub"] = "someone" })), f.client.ID },
		"expired":         func() (string, string) { return signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(func(c map[string]any) { c["iat"] = time.Now().Unix() - 400; c["exp"] = time.Now().Unix() - 100 })), f.client.ID },
		"window too long": func() (string, string) { return signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(func(c map[string]any) { c["exp"] = time.Now().Unix() + 3600 })), f.client.ID },
		"future iat":      func() (string, string) { return signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(func(c map[string]any) { c["iat"] = time.Now().Unix() + 300; c["exp"] = time.Now().Unix() + 400 })), f.client.ID },
		"unknown device":  func() (string, string) { return signDeviceAssertionForTest(t, f.priv, testHeader("dev-9"), f.claims(func(c map[string]any) { c["iss"] = "device:dev-9" })), f.client.ID },
	}
	for name, mk := range cases {
		compact, clientID := mk()
		if _, _, err := f.engine.ExchangeDeviceAssertion(compact, clientID, "127.0.0.1", "test"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestExchangeDeviceAssertionReplay(t *testing.T) {
	f := newSignOnFixture(t)
	compact := signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil))
	if _, _, err := f.engine.ExchangeDeviceAssertion(compact, f.client.ID, "127.0.0.1", "test"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.engine.ExchangeDeviceAssertion(compact, f.client.ID, "127.0.0.1", "test"); err == nil {
		t.Fatal("replayed jti accepted")
	}
}

func TestExchangeDeviceAssertionSignOnDisabled(t *testing.T) {
	f := newSignOnFixture(t)
	if err := f.db.SetNativeDeviceCanSignOn("dev-1", f.user.ID, false); err != nil {
		t.Fatal(err)
	}
	compact := signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil))
	if _, _, err := f.engine.ExchangeDeviceAssertion(compact, f.client.ID, "127.0.0.1", "test"); !errors.Is(err, ErrDeviceSignOnDisabled) {
		t.Fatalf("want ErrDeviceSignOnDisabled, got %v", err)
	}
}

func TestExchangeDeviceAssertionInactiveUser(t *testing.T) {
	f := newSignOnFixture(t)
	if _, err := f.db.DB().Exec(`UPDATE users SET status = 'disabled' WHERE id = ?`, f.user.ID); err != nil { // use the store's real accessor or an exported setter
		t.Fatal(err)
	}
	compact := signDeviceAssertionForTest(t, f.priv, testHeader("dev-1"), f.claims(nil))
	if _, _, err := f.engine.ExchangeDeviceAssertion(compact, f.client.ID, "127.0.0.1", "test"); err == nil {
		t.Fatal("inactive user issued a token")
	}
}
```

If the store exposes no raw DB handle to tests in package `oauth`, use whatever existing user-status setter the store has (`grep -n "func (s \*Store) SetUserStatus\|UpdateUser" internal/store/store.go`) instead of the raw `UPDATE`.

- [ ] **Step 3: Run to verify they fail**

Run: `go test ./internal/oauth/ -run TestExchangeDeviceAssertion -count=1`
Expected: FAIL, undefined `ExchangeDeviceAssertion`, `ErrDeviceSignOnDisabled`.

- [ ] **Step 4: Implement**

Append to `internal/oauth/device_assertion.go`:

```go
const (
	deviceAssertionMaxWindow = 300 * time.Second
	deviceAssertionSkew      = 60 * time.Second
)

var ErrDeviceSignOnDisabled = errors.New("device sign-on is disabled")

// ExchangeDeviceAssertion is the RFC 7523 jwt-bearer grant for a paired KyAuth device.
// The assertion is the client authentication: the device's enrolled key is the only
// thing that can produce it, so no client_secret is required for this grant.
func (e *Engine) ExchangeDeviceAssertion(compact, clientID, ip, userAgent string) (*TokenResponse, string, error) {
	a, input, sig, err := parseDeviceAssertion(compact)
	if err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	iat, exp := time.Unix(a.IssuedAt, 0), time.Unix(a.ExpiresAt, 0)
	switch {
	case a.ClientID != clientID:
		return nil, a.DeviceID, errors.New("client_id does not match the assertion")
	case a.Audience != e.issuerURL+"/oauth/token":
		return nil, a.DeviceID, errors.New("assertion audience is not this token endpoint")
	case iat.After(now.Add(deviceAssertionSkew)):
		return nil, a.DeviceID, errors.New("assertion issued in the future")
	case exp.Before(now.Add(-deviceAssertionSkew)):
		return nil, a.DeviceID, errors.New("assertion expired")
	case exp.Sub(iat) > deviceAssertionMaxWindow:
		return nil, a.DeviceID, errors.New("assertion validity window too long")
	}
	dev, err := e.store.GetNativeDevice(a.DeviceID)
	if err != nil {
		return nil, a.DeviceID, err
	}
	if dev == nil || dev.UserID != a.Subject || dev.PublicKey == "" {
		return nil, a.DeviceID, errors.New("unknown device for subject")
	}
	if !dev.CanSignOn {
		return nil, a.DeviceID, ErrDeviceSignOnDisabled
	}
	pub, err := crypto.ParseP256PublicKey(dev.PublicKey)
	if err != nil || !verifyES256(pub, input, sig) {
		return nil, a.DeviceID, errors.New("assertion signature invalid")
	}
	client, err := e.store.GetOAuthClientByID(clientID)
	if err != nil || client == nil || !client.Enabled {
		return nil, a.DeviceID, errors.New("unknown client")
	}
	fresh, err := e.store.ConsumeDeviceSignOnJTI(a.JTI, exp.Add(deviceAssertionSkew))
	if err != nil {
		return nil, a.DeviceID, err
	}
	if !fresh {
		return nil, a.DeviceID, errors.New("assertion replayed")
	}
	user, err := e.store.GetUserByID(a.Subject)
	if err != nil || user == nil {
		return nil, a.DeviceID, errors.New("unknown user")
	}

	// A device login session: no browser holds its token (the hash preimage is
	// discarded), it exists so sid, EnsureClientSession and back-channel logout
	// treat this sign-in like any other. FactorMethod is "push" because the
	// proof is a signature from the enrolled push-approver key.
	sessionTokenHash := crypto.HashSHA256(uuid.NewString())
	sess := &store.Session{
		ID: uuid.NewString(), UserID: user.ID, SessionTokenHash: sessionTokenHash,
		IPAddress: ip, UserAgent: userAgent, ExpiresAt: now.Add(AccessTokenTTL), CreatedAt: now, LastActiveAt: now,
		AuthenticationEvidence: store.AuthenticationEvidence{PrimaryAuthenticatedAt: &now, FactorAuthenticatedAt: &now, FactorMethod: "push"},
	}
	if err := e.store.CreateSession(sess); err != nil {
		return nil, a.DeviceID, err
	}
	scope, err := e.GrantedScope(clientID, "openid profile email")
	if err != nil {
		return nil, a.DeviceID, err
	}
	exp = now.Add(AccessTokenTTL)
	if end, err := e.store.AccessEndsAt(user.ID, clientID); err == nil && end != nil && end.Before(exp) {
		exp = *end
	}
	accessJTI := uuid.NewString()
	if err := e.store.RecordIssuedToken(&store.IssuedToken{JTI: accessJTI, UserID: user.ID, ClientID: clientID, ExpiresAt: exp, SessionID: sess.ID}); err != nil {
		return nil, a.DeviceID, err
	}
	accessToken, err := e.keyManager.SignJWT(map[string]any{
		"iss": e.issuerURL, "sub": user.ID, "aud": clientID, "exp": exp.Unix(), "iat": now.Unix(),
		"jti": accessJTI, "scope": scope, "token_use": "access_token",
	})
	if err != nil {
		return nil, a.DeviceID, err
	}
	sid, err := e.store.EnsureClientSession(clientID, sess.ID, user.ID)
	if err != nil {
		return nil, a.DeviceID, err
	}
	claims, err := e.identityClaims(user, clientID, scope)
	if err != nil {
		return nil, a.DeviceID, err
	}
	claims["sid"] = sid
	claims["exp"] = exp.Unix()
	claims["iat"] = now.Unix()
	claims["token_use"] = "id_token"
	claims["auth_time"] = now.Unix()
	claims["amr"] = []string{"hwk", "user", "urn:kysignon:amr:push", "mfa"}
	claims["acr"] = "urn:kysignon:acr:mfa"
	claims["signon_method"] = "device"
	claims["device_id"] = dev.ID
	idToken, err := e.keyManager.SignJWT(claims)
	if err != nil {
		return nil, a.DeviceID, err
	}
	_ = e.store.TouchNativeDeviceLastSeen(dev.ID, now) // add this one-line UPDATE if no equivalent exists
	return &TokenResponse{AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: int(time.Until(exp).Seconds()), IDToken: idToken, Scope: scope}, dev.ID, nil
}
```

Check the exact names before writing: the ID-token claims in `ExchangeAuthorizationCode` (oauth.go ~340-400) set `exp`, `iat`, `nonce`, `token_use`; copy the exact keys it uses so both grants issue the same shape. `GetUserByID` may be named differently (`grep -n "func (s \*Store) GetUser" internal/store/store.go`). `AccessEndsAt` is used at oauth.go ~355; match its signature. Add imports `time`, `github.com/google/uuid`, `.../internal/crypto`, `.../internal/store`. If `TouchNativeDeviceLastSeen` does not exist, add to store.go:

```go
func (s *Store) TouchNativeDeviceLastSeen(deviceID string, at time.Time) error {
	_, err := s.db.Exec(`UPDATE native_devices SET last_seen_at = ? WHERE id = ?`, at.UTC(), deviceID)
	return err
}
```

- [ ] **Step 5: Run tests**

Run: `go test ./internal/oauth/ ./internal/store/ -count=1`
Expected: PASS. If `TestExchangeDeviceAssertionIssuesIDToken` fails inside `RecordIssuedToken` with no rows, the fixture user lacks an enrolled push factor while enrollment is required: register the device through `mfa.Engine.RegisterNativeDevice` in the fixture instead of `UpsertNativeDevice`, which also creates the push MFA method.

- [ ] **Step 6: Commit**

```bash
git add internal/oauth internal/store
git commit -m "feat(oauth): jwt-bearer grant for paired device sign-on"
```

---

### Task 6: Token endpoint branch, rate limit, audit

**Files:**
- Modify: `internal/api/oauth_handlers.go:249-266`
- Modify: `internal/api/server.go:191`
- Test: `internal/api/device_signon_test.go`

**Interfaces:**
- Consumes: `ExchangeDeviceAssertion`, `ErrDeviceSignOnDisabled`.
- Produces: `POST /oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=...&client_id=...`. Errors: 400 `invalid_grant`; when sign-on is disabled, `error_description` is `device_signon_disabled` so KyAuth can tell the user what to fix.

- [ ] **Step 1: Write the failing HTTP test**

Append to `internal/api/device_signon_test.go`. Use `setupTestServer(t)` and create user, session-less device, and client with `allowTestAppAccess`. The assertion signer lives in package `oauth` tests, so duplicate the 15-line `signDeviceAssertionForTest` here as `signAssertion`:

```go
func TestTokenEndpointDeviceSignOnGrant(t *testing.T) {
	server, dbStore, _, mfaEngine, _, cleanup := setupTestServer(t)
	defer cleanup()
	user := createActiveUser(t, dbStore) // existing helper name from api_test.go; adapt
	client := &store.OAuthClient{ID: "kypost", ClientName: "KyPost", ClientType: "confidential", RedirectURIsJSON: `["https://kypost.example/cb"]`, AllowedScopesJSON: `["openid","profile","email"]`, Enabled: true}
	if err := dbStore.CreateOAuthClient(client); err != nil {
		t.Fatal(err)
	}
	allowTestAppAccess(t, dbStore, client.ID)

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	token, _, _, err := mfaEngine.GenerateDevicePairingToken(user.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := mfaEngine.RegisterNativeDevice(&mfa.NativeDeviceRegisterRequest{PairingToken: token, DeviceName: "p", DeviceIdentifier: "i", PublicKey: base64.StdEncoding.EncodeToString(spki), PushToken: "fcm"})
	if err != nil {
		t.Fatal(err)
	}

	post := func(assertion, clientID string) *httptest.ResponseRecorder {
		form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}, "client_id": {clientID}}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		server.httpServer.Handler.ServeHTTP(rec, req)
		return rec
	}
	now := time.Now().Unix()
	claims := map[string]any{"iss": "device:" + dev.ID, "sub": user.ID, "aud": server.issuerURL + "/oauth/token", "client_id": "kypost", "iat": now, "exp": now + 120, "jti": uuid.NewString()}
	rec := post(signAssertion(t, priv, dev.ID, claims), "kypost")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("token response must be no-store")
	}
	var body struct {
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.IDToken == "" || body.RefreshToken != "" {
		t.Fatalf("body %s", rec.Body.String())
	}

	if err := dbStore.SetNativeDeviceCanSignOn(dev.ID, user.ID, false); err != nil {
		t.Fatal(err)
	}
	claims["jti"] = uuid.NewString()
	rec = post(signAssertion(t, priv, dev.ID, claims), "kypost")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "device_signon_disabled") {
		t.Fatalf("disabled: status %d body %s", rec.Code, rec.Body.String())
	}
}
```

Find how the test server exposes its issuer URL (`grep -n "issuerURL" internal/api/server.go internal/api/api_test.go | head`) and use that field or a config value.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/api/ -run TestTokenEndpointDeviceSignOnGrant -count=1`
Expected: FAIL with status 400 `grant_type=authorization_code ... required`.

- [ ] **Step 3: Implement the branch**

In `oauth_handlers.go` `Token`, replace the guard at line 258 with:

```go
	if grantType == "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		h.deviceSignOn(w, r, r.FormValue("assertion"), clientID)
		return
	}
	if grantType != "authorization_code" || code == "" || clientID == "" {
```

Add:

```go
// deviceSignOn answers the jwt-bearer grant for a paired KyAuth device.
func (h *OAuthHandler) deviceSignOn(w http.ResponseWriter, r *http.Request, assertion, clientID string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if assertion == "" || clientID == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request", "error_description": "assertion and client_id are required"})
		return
	}
	ip := h.middleware.ClientIP(r)
	if !h.deviceSignOnLimiter.Allow("device_signon:" + ip) {
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "slow_down"})
		return
	}
	tokenResp, deviceID, err := h.oauthEngine.ExchangeDeviceAssertion(assertion, clientID, ip, r.UserAgent())
	if err != nil {
		h.audit.Record("device.signon", "", "", deviceID, "device", ip, r.UserAgent(), "failure", map[string]any{"clientId": clientID, "error": err.Error()})
		description := "The device assertion is invalid"
		if errors.Is(err, oauth.ErrDeviceSignOnDisabled) {
			description = "device_signon_disabled"
		}
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": description})
		return
	}
	h.audit.Record("device.signon", "", "", deviceID, "device", ip, r.UserAgent(), "success", map[string]any{"clientId": clientID})
	_ = json.NewEncoder(w).Encode(tokenResp)
}
```

Rate limiting: `/oauth/token` is already wrapped in `RateLimit("oauth_token", 30, 1.0)` per IP at `server.go:191`. The spec asks for a tighter per-device budget. Read `internal/api/middleware.go:198` to see the limiter type `RateLimit` builds; if it exposes a reusable bucket object, hold one on `OAuthHandler` as `deviceSignOnLimiter` constructed with `(10, 0.2)` and key it by `"device_signon:"+ip`. If it does not, add the smallest constructor that returns the same type the middleware uses internally. Keying by device ID as well is not possible before the assertion is parsed; IP is the pre-parse key, and `ConsumeDeviceSignOnJTI` bounds per-device replay.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/api/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api
git commit -m "feat(oauth): accept device assertions on /oauth/token"
```

---

### Task 7: Web UI toggles and docs

**Files:**
- Modify: `web/src/types.ts:52-60` (`NativeDevice` gains `canSignOn: boolean`)
- Modify: `web/src/parsers.ts:150-165` (`canSignOn: bool(o, 'canSignOn')`)
- Modify: `web/src/components/DeviceSettings.tsx` (~199-215 pairing; device list rows where `isMfaApprover` toggle renders)
- Modify: `AGENTS.md` (route table / device contract)
- Test: existing `web` test command in `web/package.json`; Go tests unchanged.

- [ ] **Step 1: Types and parser**

`types.ts`: add `canSignOn: boolean;` after `isMfaApprover`. `parsers.ts` `parseDevice`: add `canSignOn: bool(o, 'canSignOn'),`.

- [ ] **Step 2: Pairing checkbox**

In `DeviceSettings.tsx`, near line 199, add state `const [pairSignOn, setPairSignOn] = useState(true);` and a checkbox above the "Pair a phone" button labelled "Allow this phone to sign in to suite apps (KyPost, KyVault, …)". Pass it through:

```ts
const data = await apiJson('/api/user/devices/pairing-token', parsePairingToken, {
  method: 'POST', stepUpToken, body: JSON.stringify({ signOn: pairSignOn }),
});
```

Check `apiJson`'s signature accepts a `body` option and sets the JSON content type; if it takes a `json` field instead, use that.

- [ ] **Step 3: Per-device toggle**

Find where each device row renders the MFA approver switch (search `isMfaApprover` in the component). Add a sibling switch "Sign in to apps" bound to `device.canSignOn` that calls:

```ts
await apiJson(`/api/notifications/native/devices/${device.id}/sign-on`, parseSuccess, {
  method: 'PUT', body: JSON.stringify({ canSignOn: next }),
});
```

using the same `parseSuccess`-style parser the MFA toggle uses, then reload the device list the way that toggle does. Add helper copy under the switch: "Off: this phone still approves MFA but cannot sign you in to KyPost or other suite apps."

- [ ] **Step 4: Build and test the web app**

Run: `cd web && npm ci --ignore-scripts && npm run build && npm test --if-present`
Expected: build succeeds; commit the regenerated `web/dist` only if the repo tracks it (it does: `web/dist/assets/index-*.js` is checked in).

- [ ] **Step 5: Docs**

In `AGENTS.md` (repo root), in the section that lists device routes and the OAuth grant, add:

- `PUT /api/notifications/native/devices/{id}/sign-on` — session + owner; `{canSignOn}`; audited `device.sign_on_changed`.
- `POST /api/user/devices/pairing-token` accepts `{signOn}` (default true); the flag lands on the registered device as `canSignOn`.
- `POST /oauth/token` `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`: ES256 assertion signed by a native device's enrolled key (`kid` = device id, `iss` = `device:<id>`, `aud` = `<issuer>/oauth/token`, `client_id` bound, ≤300 s window, single-use `jti` in `device_signon_jtis`). Requires `can_sign_on`. Opens a device login session (`FactorMethod: push`), issues access + ID token with `signon_method: device`, `device_id`, `amr: [hwk,user,urn:kysignon:amr:push,mfa]`. No refresh token. Audited `device.signon`.

- [ ] **Step 6: Full verification and commit**

Run: `gofmt -l . && go vet ./... && go test -race -count=1 -timeout 20m ./...`
Expected: no gofmt output, vet clean, all PASS.

```bash
git add web/src web/dist AGENTS.md
git commit -m "feat(web): sign-on toggle for paired devices"
```
