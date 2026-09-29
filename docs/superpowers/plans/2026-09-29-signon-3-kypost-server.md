# kypost-server native sign-on Implementation Plan (3 of 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** kypost-server accepts a KyIdentity ID token minted by the device grant and answers with the same single-use pairing deep link the password path answers.

**Architecture:** One new `sso.Provider.VerifyIDToken` that runs `Exchange`'s go-oidc checks on a raw token, one public config field, and one `withTokenAuth` handler that verifies, spends the `jti`, resolves the user exactly as the OIDC callback does, and calls the existing `writeNotificationPairing`. Device minting, push and TLS pin paths are untouched.

**Tech Stack:** Go, `github.com/coreos/go-oidc`, existing `ssotest` fake IdP.

**Spec:** `kyauth-android/docs/superpowers/specs/2026-09-29-kyidentity-account-manager-signon-design.md`, section 3.

**Repo:** `/home/yoshi/git/busnes.app/kypost-server`, work in `backend/`. Branch: `feature/native-signon`.

## Global Constraints

- The token must satisfy everything `Exchange` checks except nonce and at_hash: signature from JWKS with `allowedSigningAlgs`, `iss`, `aud` = `ClientID`, `exp`, `nbf` skew 30 s, non-empty `sub`.
- Additionally: `signon_method == "device"`, `iat` within the last 300 s, `jti` non-empty and single-use (`s.singleUse.consume("native-signon:"+jti, ttl)`).
- Route marker is `withTokenAuth`; `route_auth_test.go` maps must name the new primitive `verifyNativeSignOnToken`.
- Metered on `s.ssoRateLimited` before any discovery fetch.
- `backend/AGENTS.md:29` rule must be amended, not contradicted.
- Never log the token. Failures answer `403 Access denied: ...` for identity refusals and `400 invalid request` for shape errors, matching the callback's wording.
- CI: `cd backend && go test -race -count=1 -timeout=20m ./...`.

## Review Focus

1. A token whose `iat` is 10 minutes old but not yet expired → refused. Pinned in Task 3 (`staleIat`).
2. A valid token presented twice → second is refused even within its lifetime. Pinned in Task 3 (`replay`).
3. A token from the browser code flow (no `signon_method`) presented to this endpoint → refused; the web flow and the device flow must not be interchangeable. Pinned in Task 3 (`webTokenRefused`).
4. SSO disabled or `PAIRING_SECRET` unset → 503/`configured:false`, never a 500. Pinned in Task 3 (`ssoOff`).
5. A user disabled by SCIM after the token was minted → the `Directory` check refuses. Pinned in Task 3 (`directoryDisabled`).

---

### Task 1: `Provider.VerifyIDToken` and an exported test token

**Files:**
- Modify: `backend/internal/sso/sso.go` (after `Exchange`, ~606)
- Modify: `backend/internal/sso/ssotest/ssotest.go` (export a token minter)
- Test: `backend/internal/sso/sso_test.go` (or the existing provider test file; `ls backend/internal/sso/*_test.go`)

**Interfaces:**
- Produces: `func (p *Provider) VerifyIDToken(ctx context.Context, raw string) (*SSOTokenClaims, error)`.
- Produces: `func (i *IdP) IDToken() string` in `ssotest` (returns exactly what `idToken()` returns).

- [ ] **Step 1: Write the failing test**

```go
func TestVerifyIDTokenRunsTheExchangeChecks(t *testing.T) {
	idp := ssotest.New(t, "kypost-test")
	previous := SetTransport(idp.Transport())
	t.Cleanup(func() { SetTransport(previous) })
	p, err := NewProvider(context.Background(), SSOSettings{Enabled: true, IssuerURL: idp.URL(), ClientID: idp.ClientID, ClientSecret: "s"}, "https://kypost.example/cb")
	if err != nil {
		t.Fatal(err)
	}
	idp.SetClaims(map[string]any{"sub": "sso-sub-12345", "preferred_username": "alice", "signon_method": "device"})
	claims, err := p.VerifyIDToken(context.Background(), idp.IDToken())
	if err != nil {
		t.Fatal(err)
	}
	if claims.Sub != "sso-sub-12345" || claims.Issuer != idp.URL() || claims.Username != "alice" {
		t.Fatalf("claims %+v", claims)
	}
	for name, mutate := range map[string]func(){
		"unsigned":       func() { idp.Unsigned = true },
		"foreign key":    func() { idp.ForeignKey = true },
		"alg none":       func() { idp.AlgNone = true },
		"expired":        func() { idp.Expired = true },
		"wrong audience": func() { idp.WrongAudience = "someone-else" },
		"wrong issuer":   func() { idp.WrongIssuer = "https://evil.example" },
	} {
		fresh := ssotest.New(t, "kypost-test")
		prev := SetTransport(fresh.Transport())
		fp, err := NewProvider(context.Background(), SSOSettings{Enabled: true, IssuerURL: fresh.URL(), ClientID: fresh.ClientID, ClientSecret: "s"}, "https://kypost.example/cb")
		if err != nil {
			t.Fatal(err)
		}
		idp = fresh
		mutate()
		if _, err := fp.VerifyIDToken(context.Background(), fresh.IDToken()); err == nil {
			t.Errorf("%s: accepted", name)
		}
		SetTransport(prev)
	}
}
```

Read the existing provider test file first: if it already has a helper that builds a `Provider` against an `IdP`, use it instead of the inline `NewProvider` calls.

- [ ] **Step 2: Run to verify it fails**

Run: `cd /home/yoshi/git/busnes.app/kypost-server/backend && go test ./internal/sso/ -run TestVerifyIDTokenRunsTheExchangeChecks -count=1`
Expected: FAIL, `p.VerifyIDToken undefined`, `idp.IDToken undefined`.

- [ ] **Step 3: Implement**

`ssotest.go`:

```go
// IDToken mints a token straight from the IdP, for endpoints that accept one
// outside the browser code flow (native sign-on). Honours every tamper knob.
func (i *IdP) IDToken() string { return i.idToken() }
```

`sso.go`, after `Exchange`:

```go
// VerifyIDToken checks a raw ID token the way Exchange does, for the one caller
// that receives a token without a browser round trip: native sign-on, where
// KyAuth obtained the token from KyIdentity's device grant. There is no nonce
// to hold it to (nothing in this server started the flow) and no access token
// for at_hash; the handler binds the token with signon_method, iat age and a
// single-use jti instead.
func (p *Provider) VerifyIDToken(ctx context.Context, raw string) (*SSOTokenClaims, error) {
	ctx = oidc.ClientContext(ctx, p.client)
	idToken, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("id_token verification failed: %w", err)
	}
	var timing struct {
		NotBefore int64 `json:"nbf"`
	}
	if err := idToken.Claims(&timing); err == nil && timing.NotBefore > 0 {
		if time.Now().Add(30 * time.Second).Before(time.Unix(timing.NotBefore, 0)) {
			return nil, errors.New("id_token is not valid yet (nbf is in the future)")
		}
	}
	if strings.TrimSpace(idToken.Subject) == "" {
		return nil, errors.New("id_token carries no sub claim")
	}
	claims := &SSOTokenClaims{}
	if err := idToken.Claims(claims); err != nil {
		return nil, fmt.Errorf("unreadable id_token claims: %w", err)
	}
	claims.Sub = idToken.Subject
	claims.Issuer = idToken.Issuer
	normalizeUsername(claims)
	return claims, nil
}
```

Add to `SSOTokenClaims` (sso.go:255-285):

```go
	// SignOnMethod is "device" on tokens KyIdentity minted from a paired phone's
	// assertion; absent on browser logins. JTI is the token id those carry.
	SignOnMethod string `json:"signon_method"`
	JTI          string `json:"jti"`
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/sso/... -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/sso
git commit -m "feat(sso): verify a raw ID token for native sign-on"
```

---

### Task 2: `clientId` in the public SSO config

**Files:**
- Modify: `backend/internal/api/sso_handlers.go:52-58`
- Test: `backend/internal/api/sso_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestSSOConfigExposesClientID(t *testing.T) {
	srv, idp := setupSSOTestServer(t)
	rec := httptest.NewRecorder()
	srv.handleSSOConfig(rec, httptest.NewRequest(http.MethodGet, "/api/auth/sso-config", nil))
	var body struct {
		Enabled   bool   `json:"enabled"`
		IssuerURL string `json:"issuerUrl"`
		ClientID  string `json:"clientId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Enabled || body.IssuerURL != idp.URL() || body.ClientID != idp.ClientID {
		t.Fatalf("body %+v", body)
	}
	if strings.Contains(rec.Body.String(), "test-secret") {
		t.Fatal("client secret leaked")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/api/ -run TestSSOConfigExposesClientID -count=1`
Expected: FAIL, `ClientID` empty.

- [ ] **Step 3: Implement**

```go
func (s *Server) handleSSOConfig(w http.ResponseWriter, r *http.Request) {
	settings := s.ssoStore.Load()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":   settings.Enabled,
		"issuerUrl": settings.IssuerURL,
		"clientId":  settings.ClientID,
	})
}
```

- [ ] **Step 4: Run tests, commit**

Run: `go test ./internal/api/ -run TestSSOConfig -count=1` → PASS.

```bash
git add internal/api/sso_handlers.go internal/api/sso_test.go
git commit -m "feat(sso): publish clientId in the public SSO config"
```

---

### Task 3: `POST /api/auth/native/signon`

**Files:**
- Create: `backend/internal/api/native_signon.go`
- Modify: `backend/internal/api/server.go` (route, next to line 721)
- Modify: `backend/internal/api/route_auth_test.go:121,224` (marker maps)
- Modify: `backend/internal/api/route_auth_markers.go:34` comment
- Test: `backend/internal/api/native_signon_test.go`

**Interfaces:**
- Consumes: `Provider.VerifyIDToken`, `s.ssoProvider(r, settings)`, `s.ssoLifecycle.Directory/LoggedOut`, `s.resolveSSOUser`, `s.writeNotificationPairing`, `s.singleUse.consume`, `s.ssoRateLimited`.
- Produces: `POST /api/auth/native/signon` body `{"idToken": "..."}` → same JSON as review-pairing (`deepLink`, `pairingToken`, ...). `verifyNativeSignOnToken(w, r) (*sso.SSOTokenClaims, sso.SSOSettings, bool)` is the auth primitive named in the marker maps.

- [ ] **Step 1: Write the failing tests**

`native_signon_test.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func signOnRequest(idToken string) *http.Request {
	body, _ := json.Marshal(map[string]string{"idToken": idToken})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/native/signon", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func deviceClaims(extra map[string]any) map[string]any {
	c := map[string]any{"sub": "sso-sub-12345", "preferred_username": "alice", "signon_method": "device", "jti": "jti-1", "iat": time.Now().Unix()}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

func TestNativeSignOnReturnsPairingDeepLink(t *testing.T) {
	srv, idp := setupSSOTestServer(t)
	srv.pairingSecret = "pairing-secret"
	idp.SetClaims(deviceClaims(nil))

	rec := httptest.NewRecorder()
	srv.handleNativeSignOn(rec, signOnRequest(idp.IDToken()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var body struct {
		DeepLink   string `json:"deepLink"`
		Configured bool   `json:"configured"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if !body.Configured || !strings.HasPrefix(body.DeepLink, "kypost://native-pair?") {
		t.Fatalf("body %s", rec.Body.String())
	}
	if _, err := srv.users.GetByUsername("alice"); err != nil {
		t.Fatalf("auto-provisioned user missing: %v", err)
	}

	// replay: same token, same jti
	rec = httptest.NewRecorder()
	srv.handleNativeSignOn(rec, signOnRequest(idp.IDToken()))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("replay status %d", rec.Code)
	}
}

func TestNativeSignOnRefusals(t *testing.T) {
	cases := map[string]struct {
		claims map[string]any
		setup  func(*Server)
		want   int
	}{
		"webTokenRefused":   {claims: deviceClaims(map[string]any{"signon_method": nil}), want: http.StatusForbidden},
		"staleIat":          {claims: deviceClaims(map[string]any{"iat": time.Now().Add(-10 * time.Minute).Unix(), "jti": "jti-stale"}), want: http.StatusForbidden},
		"missingJti":        {claims: deviceClaims(map[string]any{"jti": nil}), want: http.StatusForbidden},
		"ssoOff":            {claims: deviceClaims(nil), setup: func(s *Server) { st := s.ssoStore.Load(); st.Enabled = false; _ = s.ssoStore.Save(st) }, want: http.StatusServiceUnavailable},
		"pairingUnconfigured": {claims: deviceClaims(nil), setup: func(s *Server) { s.pairingSecret = "" }, want: http.StatusServiceUnavailable},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv, idp := setupSSOTestServer(t)
			srv.pairingSecret = "pairing-secret"
			if tc.setup != nil {
				tc.setup(srv)
			}
			claims := tc.claims
			for k, v := range claims {
				if v == nil {
					delete(claims, k)
				}
			}
			idp.SetClaims(claims)
			rec := httptest.NewRecorder()
			srv.handleNativeSignOn(rec, signOnRequest(idp.IDToken()))
			if rec.Code != tc.want {
				t.Fatalf("status %d want %d body %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestNativeSignOnDirectoryDisabled(t *testing.T) {
	srv, idp := setupSSOTestServer(t)
	srv.pairingSecret = "pairing-secret"
	idp.SetClaims(deviceClaims(nil))
	// Mirror whatever sso_test.go does to record a SCIM-disabled directory entry
	// for sub "sso-sub-12345" (grep "Directory(" and "Active: false" in sso_test.go
	// and reuse that helper verbatim).
	markDirectoryDisabled(t, srv, idp.URL(), "sso-sub-12345")
	rec := httptest.NewRecorder()
	srv.handleNativeSignOn(rec, signOnRequest(idp.IDToken()))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}
```

If `writeNotificationPairing` needs `serverBaseURL` (it does, for the register endpoint), `setupSSOTestServer` already sets `srv.serverBaseURL`. If `pairingSecret` is not a plain field, set it the way `review_pairing_test.go` does.

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/api/ -run TestNativeSignOn -count=1`
Expected: FAIL, `handleNativeSignOn` undefined.

- [ ] **Step 3: Implement**

`native_signon.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/.../kypost-server/backend/internal/sso" // match the module path used by sso_handlers.go
)

const nativeSignOnMaxAge = 5 * time.Minute

// handleNativeSignOn turns a KyIdentity device-grant ID token into the same
// single-use pairing deep link the password path mints. The token is the whole
// credential, so the route is withTokenAuth; verifyNativeSignOnToken is the
// primitive the route-marker test looks for.
func (s *Server) handleNativeSignOn(w http.ResponseWriter, r *http.Request) {
	claims, settings, ok := s.verifyNativeSignOnToken(w, r)
	if !ok {
		return
	}
	if s.pairingSecret == "" || s.pairingBaseURL() == "" {
		http.Error(w, "pairing is not configured on the server", http.StatusServiceUnavailable)
		return
	}

	directory, known, err := s.ssoLifecycle.Directory(settings.IssuerURL, claims.Sub)
	if err != nil {
		s.ssoFailure(w, "lifecycle", err)
		return
	}
	if known && !directory.Active {
		http.Error(w, "Access denied: your account was disabled by the directory.", http.StatusForbidden)
		return
	}
	if known && claims.IssuedAt < directory.RevokedBefore {
		http.Error(w, "Access denied: your directory access changed. Sign in again.", http.StatusForbidden)
		return
	}
	user, err := s.resolveSSOUser(w, settings, claims)
	if err != nil {
		return
	}
	if !user.Active {
		http.Error(w, "Access denied: your KyPost account is deactivated.", http.StatusForbidden)
		return
	}
	identity := sso.SessionIdentity{Issuer: claims.Issuer, ClientID: settings.ClientID, Subject: claims.Sub, SessionID: claims.SessionID, IssuedAt: time.Unix(claims.IssuedAt, 0)}
	loggedOut, err := s.ssoLifecycle.LoggedOut(identity)
	if err != nil {
		s.ssoFailure(w, "lifecycle", err)
		return
	}
	if loggedOut {
		http.Error(w, "Access denied: this sign-in was ended by the identity provider. Sign in again.", http.StatusForbidden)
		return
	}
	s.writeNotificationPairing(w, user.ID)
}

// verifyNativeSignOnToken authenticates the request. It returns ok=false after
// writing the response. Order: rate limit, SSO on, body shape, signature and
// claims via go-oidc, device binding, freshness, single use.
func (s *Server) verifyNativeSignOnToken(w http.ResponseWriter, r *http.Request) (*sso.SSOTokenClaims, sso.SSOSettings, bool) {
	settings := s.ssoStore.Load()
	if s.ssoRateLimited(w, r) {
		return nil, settings, false
	}
	if !settings.Enabled || settings.IssuerURL == "" || settings.ClientID == "" {
		http.Error(w, "single sign-on is not configured", http.StatusServiceUnavailable)
		return nil, settings, false
	}
	var req struct {
		IDToken string `json:"idToken"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil || strings.TrimSpace(req.IDToken) == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return nil, settings, false
	}
	provider, _, err := s.ssoProvider(r, settings)
	if err != nil {
		s.ssoFailure(w, "provider", err)
		return nil, settings, false
	}
	claims, err := provider.VerifyIDToken(r.Context(), req.IDToken)
	if err != nil {
		http.Error(w, "Access denied: the identity token could not be verified.", http.StatusForbidden)
		return nil, settings, false
	}
	if claims.SignOnMethod != "device" || claims.JTI == "" {
		http.Error(w, "Access denied: this token was not issued for device sign-in.", http.StatusForbidden)
		return nil, settings, false
	}
	age := time.Since(time.Unix(claims.IssuedAt, 0))
	if claims.IssuedAt == 0 || age > nativeSignOnMaxAge || age < -30*time.Second {
		http.Error(w, "Access denied: the identity token is too old. Sign in again.", http.StatusForbidden)
		return nil, settings, false
	}
	if !s.singleUse.consume("native-signon:"+claims.JTI, nativeSignOnMaxAge+time.Minute) {
		http.Error(w, "Access denied: this token was already used.", http.StatusForbidden)
		return nil, settings, false
	}
	return claims, settings, true
}
```

Confirm `s.ssoProvider` returns `(*sso.Provider, string, error)` (sso_handlers.go:116) and `s.ssoFailure`'s signature; match both. Confirm `s.pairingSecret`, `s.pairingBaseURL()` and `s.singleUse` are the real field names (`server_notifications.go:365`, `single_use.go`).

`server.go`, next to line 721:

```go
	mux.HandleFunc("POST /api/auth/native/signon", withTokenAuth(s.handleNativeSignOn))
```

`route_auth_test.go`: add `"verifyNativeSignOnToken"` to the `withTokenAuth` slice in `markerRequiresCall` (line 121) and `"verifyNativeSignOnToken": {"withTokenAuth"},` to `authPrimitives` (line 224). `route_auth_markers.go:31-34` comment: add "in the body for native sign-on (`verifyNativeSignOnToken`)".

- [ ] **Step 4: Run tests**

Run: `go test ./internal/api/ -count=1`
Expected: PASS, including `TestEveryRouteDeclaresItsAuthModel` and `TestAuthMarkersMatchTheirHandlers`.

- [ ] **Step 5: Commit**

```bash
git add internal/api/native_signon.go internal/api/native_signon_test.go internal/api/server.go internal/api/route_auth_test.go internal/api/route_auth_markers.go
git commit -m "feat(auth): native sign-on with a KyIdentity device token"
```

---

### Task 4: Docs

**Files:**
- Modify: `backend/AGENTS.md:29` (ID token rule) and the route table near line 161.

- [ ] **Step 1: Amend the rule**

Replace the opening of line 29 with: "**An ID token is only ever accepted through `sso.Provider.Exchange` or `sso.Provider.VerifyIDToken`, both of which delegate verification to `github.com/coreos/go-oidc`.** `VerifyIDToken` exists for exactly one caller, `verifyNativeSignOnToken`, which receives a token KyAuth obtained from KyIdentity's device grant with no browser round trip; it skips the nonce and at_hash checks that only a code flow can make and replaces them with `signon_method == device`, an `iat` no older than five minutes and a single-use `jti`." Keep the rest of the paragraph.

- [ ] **Step 2: Route table row**

Add after the `GET /api/auth/sso-config` row (update that row's description to `{enabled, issuerUrl, clientId}`):

`| POST /api/auth/native/signon | signed token | Body {idToken}: a KyIdentity ID token from the device grant. Verified by VerifyIDToken, bound by signon_method=device, iat ≤ 5 min and single-use jti (s.singleUse "native-signon:"), then the callback's directory, resolveSSOUser and LoggedOut checks. Answers exactly what review-pairing answers: writeNotificationPairing's single-use 90-second deep link. Metered on the SSO per-IP limiter; 503 when SSO or pairing is unconfigured |`

- [ ] **Step 3: Full verification and commit**

Run: `go test -race -count=1 -timeout=20m ./...`
Expected: PASS.

```bash
git add AGENTS.md
git commit -m "docs: native sign-on route and the VerifyIDToken rule"
```
