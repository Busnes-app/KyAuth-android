package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// One shared fixture: every peer is calibrated exactly once, so the request and byte
// counters a test asserts are the ones its own traffic produced.
var shared *fixture

func TestMain(m *testing.M) {
	f, err := newFixture()
	if err != nil {
		fmt.Fprintln(os.Stderr, "fixture:", err)
		os.Exit(1)
	}
	shared = f
	code := m.Run()
	f.close()
	os.Exit(code)
}

func specOf(t *testing.T, id string) spec {
	t.Helper()
	for _, s := range specs {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("no spec %q", id)
	return spec{}
}

func peerOf(t *testing.T, id string) *peer {
	t.Helper()
	p, ok := shared.peers[id]
	if !ok {
		t.Fatalf("no case %q", id)
	}
	return p
}

// meetsFloor mirrors the application key predicate: RSA >= 2048, EC >= 256, and any
// other key type refused. Calibration asserts the fixture really sits on each side.
func meetsFloor(pub crypto.PublicKey) bool {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen() >= 2048
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize >= 256
	}
	return false
}

func checkKeySpec(t *testing.T, want string, pub crypto.PublicKey) {
	t.Helper()
	switch want {
	case "rsa1024", "rsa2047", "rsa2048":
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("key %T is not RSA", pub)
		}
		bits := map[string]int{"rsa1024": 1024, "rsa2047": 2047, "rsa2048": 2048}[want]
		if k.N.BitLen() != bits {
			t.Fatalf("actual modulus bits=%d want=%d", k.N.BitLen(), bits)
		}
	case "p224", "p256", "p384", "p521":
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("key %T is not ECDSA", pub)
		}
		curve := map[string]elliptic.Curve{"p224": elliptic.P224(), "p256": elliptic.P256(), "p384": elliptic.P384(), "p521": elliptic.P521()}[want]
		if k.Curve != curve {
			t.Fatalf("actual curve=%s want=%s", k.Curve.Params().Name, curve.Params().Name)
		}
	case "ed25519":
		if _, ok := pub.(ed25519.PublicKey); !ok {
			t.Fatalf("key %T is not Ed25519", pub)
		}
	default:
		t.Fatalf("unknown key spec %q", want)
	}
}

// calibrationHost is the name this case's certificate can actually be verified under:
// the real SAN for a wrong-host control, the reserved name for a named case, otherwise
// loopback. A wrong-host control is deliberately reached under a name it does not carry,
// so calibration has to use the SAN instead to prove the peer is otherwise sound.
func calibrationHost(s spec) string {
	if s.Flaw == flawWrongHost {
		return wrongHostSAN
	}
	if s.Host != "" {
		return s.Host
	}
	return "127.0.0.1"
}

// calibrationClient speaks to one peer under the name and trust that peer expects.
// It never skips verification: that case's own published anchor is trusted here on
// purpose -- its issuing CA, or the leaf itself for a directly trusted case -- and the
// expired control is verified at a host-chosen time inside the leaf's validity.
//
// A reserved-name case is reached the way the device reaches it, through the control
// CONNECT proxy. .invalid never resolves, so a handshake that completes under that name
// proves the proxy carried it; everything else dials loopback directly.
func calibrationClient(p *peer, s spec) (*http.Client, string) {
	roots := x509.NewCertPool()
	roots.AddCert(p.anchorCert)
	min, max := s.Min, s.Max
	if min == 0 {
		min = tls.VersionTLS12
	}
	if max == 0 {
		max = tls.VersionTLS13
	}
	cfg := &tls.Config{RootCAs: roots, MinVersion: min, MaxVersion: max}
	if min < tls.VersionTLS12 {
		cfg.CipherSuites = legacySuites
	}
	if s.Flaw == flawExpired {
		at := p.leaf.NotBefore.Add(p.leaf.NotAfter.Sub(p.leaf.NotBefore) / 2)
		cfg.Time = func() time.Time { return at }
	}
	host := calibrationHost(s)
	tr := &http.Transport{TLSClientConfig: cfg}
	if s.Host != "" && s.Flaw != flawWrongHost {
		tr.Proxy = http.ProxyURL(&url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", shared.port)})
	} else {
		addr := fmt.Sprintf("127.0.0.1:%d", p.Port)
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
	}
	return &http.Client{Transport: tr, Timeout: 20 * time.Second}, fmt.Sprintf("https://%s:%d/probe", host, p.Port)
}

func probe(t *testing.T, c *http.Client, url string) *http.Response {
	t.Helper()
	resp, err := c.Post(url, "application/json", strings.NewReader(`{"probe":"public-fixture"}`))
	if err != nil {
		t.Fatalf("calibration handshake failed: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != `{"ok":true}` {
		t.Fatalf("body=%q err=%v", body, err)
	}
	return resp
}

// TestPeerCalibration proves every served peer is a genuine, usable TLS endpoint with
// the key sizes, chain shape and protocol version it advertises. Native refusal can
// only be read as policy once this passes.
func TestPeerCalibration(t *testing.T) {
	for _, s := range specs {
		if s.Kind == kindCertificateOnly || s.Kind == kindRedirect {
			continue // redirect pair is calibrated as a pair below
		}
		t.Run(s.ID, func(t *testing.T) {
			p := peerOf(t, s.ID)
			c, url := calibrationClient(p, s)
			defer c.CloseIdleConnections()
			resp := probe(t, c, url)
			st := resp.TLS
			if st == nil {
				t.Fatal("no TLS state")
			}

			wantMax := s.Max
			if wantMax == 0 {
				wantMax = tls.VersionTLS13
			}
			if st.Version != wantMax {
				t.Fatalf("negotiated version %#04x want %#04x (%s)", st.Version, wantMax, p.TLSMax)
			}

			// The wire chain is exactly what /cases publishes.
			if len(st.PeerCertificates) != len(p.Chain) {
				t.Fatalf("wire chain %d certificates, /cases publishes %d", len(st.PeerCertificates), len(p.Chain))
			}
			for i, c := range st.PeerCertificates {
				if got := base64.StdEncoding.EncodeToString(c.Raw); got != p.Chain[i] {
					t.Fatalf("wire certificate %d differs from the published chain entry", i)
				}
			}
			checkKeySpec(t, s.Leaf, st.PeerCertificates[0].PublicKey)
			path := st.VerifiedChains[0]

			if s.Direct {
				// Directly trusted: the anchor and the served leaf are one certificate,
				// so it is on the wire by definition and the verified path adds nothing.
				if len(st.PeerCertificates) != 1 || !st.PeerCertificates[0].Equal(p.anchorCert) {
					t.Fatalf("directly trusted case sent %d certificates and they are not the anchor itself", len(st.PeerCertificates))
				}
				if st.PeerCertificates[0].IsCA || !st.PeerCertificates[0].BasicConstraintsValid {
					t.Fatal("a directly trusted anchor must be an end-entity certificate asserting CA:FALSE")
				}
				if len(path) != 1 || !path[0].Equal(p.anchorCert) {
					t.Fatalf("verified path length %d, want the directly trusted leaf alone", len(path))
				}
			} else {
				// The anchor is a CA the peer never sends; the verified path adds it.
				for _, c := range st.PeerCertificates {
					if c.Equal(p.anchorCert) {
						t.Fatal("the trust anchor was sent on the wire")
					}
				}
				if s.Inter != "" {
					if len(st.PeerCertificates) != 2 {
						t.Fatalf("chain case sent %d certificates, want leaf and intermediate", len(st.PeerCertificates))
					}
					checkKeySpec(t, s.Inter, st.PeerCertificates[1].PublicKey)
				}
				checkKeySpec(t, s.Root, p.anchorCert.PublicKey)
				if !p.anchorCert.IsCA {
					t.Fatal("a CA-signed case must be anchored at a CA certificate")
				}
				if len(path) != len(st.PeerCertificates)+1 || !path[len(path)-1].Equal(p.anchorCert) {
					t.Fatalf("verified path length %d does not end at the published anchor", len(path))
				}
			}
			if p.Anchor != "" && p.Anchor != base64.StdEncoding.EncodeToString(p.anchorCert.Raw) {
				t.Fatal("published anchor does not match the verifying anchor")
			}

			// The floor the application applies to the whole evaluated path.
			weak := 0
			for _, c := range path {
				if !meetsFloor(c.PublicKey) {
					weak++
				}
			}
			switch s.Kind {
			case kindPositive:
				if weak != 0 {
					t.Fatalf("%d certificates in a positive case are below the floor", weak)
				}
			case kindWeak:
				if weak == 0 {
					t.Fatal("a weak case has no certificate below the floor")
				}
			}

			if p.listener.accepted.Load() < 1 || p.requests.Load() != 1 || p.bytes.Load() == 0 {
				t.Fatalf("calibration did not reach HTTP: %v", p.stats())
			}

			// The peer saw the name the client dialled. A client addressing an IP
			// literal must send no SNI at all, so loopback cases observe "".
			wantSNI := calibrationHost(s)
			if net.ParseIP(wantSNI) != nil {
				wantSNI = ""
			}
			if got := p.observedSNI(); got != wantSNI {
				t.Fatalf("peer observed SNI %q, want %q", got, wantSNI)
			}
		})
	}
}

// TestRedirectReachesSeparateTarget proves the redirect source and its target are two
// owned peers with independent counters.
func TestRedirectReachesSeparateTarget(t *testing.T) {
	src, dst := peerOf(t, "redirect"), peerOf(t, "redirect_target")
	if src.RedirectTo != "redirect_target" || src.Port == dst.Port {
		t.Fatalf("redirect %d -> %q target %d is not a separate peer", src.Port, src.RedirectTo, dst.Port)
	}
	roots := x509.NewCertPool()
	roots.AddCert(src.anchorCert)
	roots.AddCert(dst.anchorCert)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	resp := probe(t, c, fmt.Sprintf("https://127.0.0.1:%d/probe", src.Port))
	if got := resp.Request.URL.Port(); got != fmt.Sprint(dst.Port) {
		t.Fatalf("final request went to port %s, want the redirect target %d", got, dst.Port)
	}
	if src.requests.Load() != 1 || dst.requests.Load() != 1 {
		t.Fatalf("counters are not separate: source %v target %v", src.stats(), dst.stats())
	}
	if src.bytes.Load() == 0 || dst.bytes.Load() == 0 {
		t.Fatalf("one peer saw no application bytes: source %v target %v", src.stats(), dst.stats())
	}
}

// TestDirectlyTrustedLeaves proves the direct-trust cases are what their name claims:
// one self-signed, explicitly non-CA end-entity certificate that is simultaneously the
// served leaf and the published trust anchor. CA-signed cases must not claim it.
func TestDirectlyTrustedLeaves(t *testing.T) {
	want := map[string]string{"trusted_rsa1024": "rsa1024", "trusted_rsa2047": "rsa2047", "trusted_rsa2048": "rsa2048"}
	seen := map[string]bool{}
	for _, s := range specs {
		p := peerOf(t, s.ID)
		if p.DirectTrust != s.Direct {
			t.Fatalf("%s: /cases direct_trust=%v but spec Direct=%v", s.ID, p.DirectTrust, s.Direct)
		}
		if !s.Direct {
			continue
		}
		seen[s.ID] = true
		leafSpec, ok := want[s.ID]
		if !ok {
			t.Fatalf("unexpected directly trusted case %q", s.ID)
		}
		if s.Leaf != leafSpec || s.Root != "" || s.Inter != "" || s.Flaw != "" {
			t.Fatalf("%s: want an unflawed self-issued %s leaf, got %+v", s.ID, leafSpec, s)
		}
		// Self-signed in the literal sense: its own key verifies its own signature.
		if err := p.leaf.CheckSignature(p.leaf.SignatureAlgorithm, p.leaf.RawTBSCertificate, p.leaf.Signature); err != nil {
			t.Fatalf("%s: leaf is not self-signed: %v", s.ID, err)
		}
		if p.leaf.IsCA || !p.leaf.BasicConstraintsValid {
			t.Fatalf("%s: the anchor must be an end-entity certificate asserting CA:FALSE", s.ID)
		}
		if !p.anchorCert.Equal(p.leaf) {
			t.Fatalf("%s: the published anchor is not the served leaf", s.ID)
		}
		if len(p.Chain) != 1 {
			t.Fatalf("%s: wire chain is %d certificates, want the leaf alone", s.ID, len(p.Chain))
		}
		if p.Anchor != p.Chain[0] {
			t.Fatalf("%s: the published anchor is not byte-identical to the served leaf", s.ID)
		}
		// Exact literal key size, at the certificate that is both leaf and anchor.
		checkKeySpec(t, leafSpec, p.anchorCert.PublicKey)
	}
	if len(seen) != len(want) {
		t.Fatalf("directly trusted cases present: %v, want %v", seen, want)
	}
}

// TestP224IsCertificateOnly records the exact host limitation instead of inventing a
// TLS negative: the certificate is genuine, crypto/tls will not serve it.
func TestP224IsCertificateOnly(t *testing.T) {
	s := specOf(t, "p224")
	p := peerOf(t, "p224")
	if p.Port != 0 || p.Kind != kindCertificateOnly || p.TLSMin != "" {
		t.Fatalf("p224 must not advertise a peer: %+v", p)
	}
	der, err := base64.StdEncoding.DecodeString(p.Chain[0])
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("published certificate does not parse: %v", err)
	}
	checkKeySpec(t, "p224", leaf.PublicKey)

	cert, root, err := build(s)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	errs := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errs <- err
			return
		}
		defer c.Close()
		errs <- tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}).Handshake()
	}()
	roots := x509.NewCertPool()
	roots.AddCert(root)
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, ServerName: "127.0.0.1"})
	if err == nil {
		conn.Close()
		t.Fatal("crypto/tls served a P-224 certificate; p224 should become a real peer")
	}
	serverErr := <-errs
	if serverErr == nil || !strings.Contains(serverErr.Error(), "unsupported certificate curve (P-224)") {
		t.Fatalf("unexpected host limitation: %v", serverErr)
	}
	t.Logf("host limitation: %v", serverErr)
}

// TestPublishedResourcesArePublic proves the generated directory carries trust anchors
// and metadata only, and that the untrusted control's root is withheld.
func TestPublishedResourcesArePublic(t *testing.T) {
	out := t.TempDir()
	if err := shared.writeResources(out); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"AndroidManifest.xml", "res/xml/tls_fixture_security.xml", "res/raw/tls_fixture_roots.pem", "ready.json"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	err := filepath.WalkDir(out, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte("PRIVATE KEY")) {
			t.Fatalf("%s contains private key material", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	anchors, err := os.ReadFile(filepath.Join(out, "res/raw/tls_fixture_roots.pem"))
	if err != nil {
		t.Fatal(err)
	}
	published := map[string]bool{}
	for rest := anchors; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			t.Fatal("anchors file has trailing non-PEM data")
		}
		if block.Type != "CERTIFICATE" {
			t.Fatalf("anchors file holds a %q block", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			t.Fatalf("anchor does not parse: %v", err)
		}
		published[base64.StdEncoding.EncodeToString(block.Bytes)] = true
	}
	for id, p := range shared.peers {
		anchor := base64.StdEncoding.EncodeToString(p.anchorCert.Raw)
		if (p.Anchor != "") != published[anchor] {
			t.Fatalf("case %s: anchor field and published anchors disagree", id)
		}
	}
	if u := peerOf(t, "untrusted"); u.Anchor != "" || published[base64.StdEncoding.EncodeToString(u.anchorCert.Raw)] {
		t.Fatal("the untrusted control's root must not be published")
	}
	if len(published) != len(shared.peers)-1 {
		t.Fatalf("published %d anchors for %d cases", len(published), len(shared.peers))
	}

	var ready struct {
		ControlPort int              `json:"control_port"`
		Cases       map[string]*peer `json:"cases"`
	}
	data, err := os.ReadFile(filepath.Join(out, "ready.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &ready); err != nil {
		t.Fatal(err)
	}
	if ready.ControlPort != shared.port || len(ready.Cases) != len(shared.peers) {
		t.Fatalf("ready.json control_port=%d cases=%d", ready.ControlPort, len(ready.Cases))
	}
}

// TestControlEndpoints pins the wire contract the Android test reads.
func TestControlEndpoints(t *testing.T) {
	base := fmt.Sprintf("http://127.0.0.1:%d", shared.port)
	var cases map[string]*peer
	getJSON(t, base+"/cases", &cases)
	if len(cases) != len(shared.peers) {
		t.Fatalf("/cases returned %d of %d", len(cases), len(shared.peers))
	}
	for id, c := range cases {
		if len(c.Chain) == 0 || c.Kind == "" {
			t.Fatalf("/cases %s has no kind or chain: %+v", id, c)
		}
		if (c.Port == 0) != (c.Kind == kindCertificateOnly) {
			t.Fatalf("/cases %s port %d disagrees with kind %s", id, c.Port, c.Kind)
		}
		if c.Host != shared.peers[id].Host || c.Pinned != shared.peers[id].Pinned {
			t.Fatalf("/cases %s host/pin metadata differs from the served peer: %+v", id, c)
		}
	}
	var stats map[string]map[string]int64
	getJSON(t, base+"/stats", &stats)
	for id := range shared.peers {
		s, ok := stats[id]
		if !ok {
			t.Fatalf("/stats is missing %s", id)
		}
		for _, k := range []string{"connections", "requests", "bytes"} {
			if _, ok := s[k]; !ok {
				t.Fatalf("/stats %s is missing %q", id, k)
			}
		}
	}
	var names map[string]string
	getJSON(t, base+"/sni", &names)
	for id, p := range shared.peers {
		got, ok := names[id]
		if !ok {
			t.Fatalf("/sni is missing %s", id)
		}
		if got != p.observedSNI() {
			t.Fatalf("/sni %s = %q, peer observed %q", id, got, p.observedSNI())
		}
	}

	resp, err := http.Get(base + "/nope")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown control path returned %d", resp.StatusCode)
	}
}

func getJSON(t *testing.T, url string, into any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		t.Fatalf("%s: %v", url, err)
	}
}

// TestReservedNameCases proves the three reserved-name cases differ from each other in
// exactly one variable each: named carries a matching DNS SAN, named_wrong_host is the
// same case with a SAN it cannot match, and pinned differs only by the generated pin.
// All three are strong, so a native refusal is a name or pin result, never a key result.
func TestReservedNameCases(t *testing.T) {
	want := map[string]struct {
		host, san, kind string
		pinned          bool
	}{
		"named":            {namedHost, namedHost, kindPositive, false},
		"named_wrong_host": {namedHost, wrongHostSAN, kindTrust, false},
		"pinned":           {pinnedHost, pinnedHost, kindTrust, true},
	}
	seen := map[string]bool{}
	for _, s := range specs {
		if s.Host == "" {
			continue
		}
		w, ok := want[s.ID]
		if !ok {
			t.Fatalf("unexpected reserved-name case %q", s.ID)
		}
		seen[s.ID] = true
		p := peerOf(t, s.ID)
		if s.Host != w.host || p.Host != w.host || p.Kind != w.kind || p.Pinned != w.pinned {
			t.Fatalf("%s: host=%q kind=%q pinned=%v, want %+v", s.ID, p.Host, p.Kind, p.Pinned, w)
		}
		// Name only: an IP SAN would let a failed name check still succeed.
		if len(p.leaf.IPAddresses) != 0 || len(p.leaf.DNSNames) != 1 || p.leaf.DNSNames[0] != w.san {
			t.Fatalf("%s: SANs IP=%v DNS=%v, want DNS %q alone", s.ID, p.leaf.IPAddresses, p.leaf.DNSNames, w.san)
		}
		if err := p.leaf.VerifyHostname(w.host); (err == nil) != (w.san == w.host) {
			t.Fatalf("%s: VerifyHostname(%q) = %v, SAN is %q", s.ID, w.host, err, w.san)
		}
		checkKeySpec(t, "rsa2048", p.leaf.PublicKey)
		if !meetsFloor(p.leaf.PublicKey) || !meetsFloor(p.anchorCert.PublicKey) {
			t.Fatalf("%s: leaf and anchor must both meet the key floor", s.ID)
		}
		if p.Anchor == "" {
			t.Fatalf("%s: anchor must be published so trust is not the variable", s.ID)
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("reserved-name cases present: %v, want %v", seen, want)
	}
}

// connectVia sends one CONNECT to the control proxy and returns its response.
func connectVia(t *testing.T, authority string) *http.Response {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", shared.port), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: authority}, Host: authority}
	if err := req.Write(c); err != nil {
		t.Fatalf("CONNECT %s: %v", authority, err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		t.Fatalf("CONNECT %s: %v", authority, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// TestControlProxyIsAnExactAllowlist proves the CONNECT proxy forwards the declared case
// host:port pairs and nothing else -- not another case's port under a declared name, not
// the same owned peer addressed as loopback, and not the control plane itself.
// The TLS calibration explicitly selects this proxy and checks observed SNI;
// it needs no external DNS lookup or host resolver assumption.
func TestControlProxyIsAnExactAllowlist(t *testing.T) {
	named, wrong, pinned := peerOf(t, "named"), peerOf(t, "named_wrong_host"), peerOf(t, "pinned")
	port := func(p *peer) string { return strconv.Itoa(p.Port) }
	for _, a := range []string{
		net.JoinHostPort(namedHost, port(named)),
		net.JoinHostPort(namedHost, port(wrong)),
		net.JoinHostPort(pinnedHost, port(pinned)),
	} {
		if resp := connectVia(t, a); resp.StatusCode != http.StatusOK {
			t.Fatalf("declared destination %s refused with %d", a, resp.StatusCode)
		}
	}
	for _, a := range []string{
		net.JoinHostPort(namedHost, port(pinned)),              // declared name, another case's port
		net.JoinHostPort(pinnedHost, port(named)),              //
		net.JoinHostPort(namedHost, "443"),                     // declared name, undeclared port
		net.JoinHostPort("127.0.0.1", port(named)),             // the owned peer, not by its declared name
		net.JoinHostPort("127.0.0.1", port(peerOf(t, "p256"))), // a peer that declares no name
		net.JoinHostPort("127.0.0.1", strconv.Itoa(shared.port)),
		"example.com:443",
		"localhost:443",
	} {
		if resp := connectVia(t, a); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("undeclared destination %s got %d, want 403", a, resp.StatusCode)
		}
	}
}

type nscDomainConfig struct {
	Cleartext string   `xml:"cleartextTrafficPermitted,attr"`
	Domains   []string `xml:"domain"`
	Anchors   *struct {
		Certificates []struct {
			Src          string `xml:"src,attr"`
			OverridePins string `xml:"overridePins,attr"`
		} `xml:"certificates"`
	} `xml:"trust-anchors"`
	Pins []struct {
		Digest string `xml:"digest,attr"`
		Value  string `xml:",chardata"`
	} `xml:"pin-set>pin"`
}

type nscConfig struct {
	XMLName xml.Name `xml:"network-security-config"`
	Base    struct {
		Cleartext string `xml:"cleartextTrafficPermitted,attr"`
	} `xml:"base-config"`
	DomainConfigs []nscDomainConfig `xml:"domain-config"`
}

func sameSet(t *testing.T, what string, got map[string]bool, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want exactly %v", what, got, want)
	}
	for _, w := range want {
		if !got[w] {
			t.Fatalf("%s = %v, want exactly %v", what, got, want)
		}
	}
}

// TestGeneratedNetworkSecurityConfig reads the written artifact, not the function, and
// pins what the fixture config is allowed to change: the debug build's cleartext hosts
// stay, the fixture anchors reach only loopback and the reserved names so every other
// debug host keeps platform trust, and the pinned name carries a pin nothing can match
// with overridePins unset, so the platform enforces it.
func TestGeneratedNetworkSecurityConfig(t *testing.T) {
	out := t.TempDir()
	if err := shared.writeResources(out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(out, "res/xml/tls_fixture_security.xml"))
	if err != nil {
		t.Fatal(err)
	}
	raw := string(data)
	if strings.Contains(raw, "overridePins") || strings.Contains(raw, "debug-overrides") {
		t.Fatalf("the generated config waives pinning: %s", raw)
	}
	var cfg nscConfig
	if err := xml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("generated config does not parse: %v\n%s", err, raw)
	}
	if cfg.Base.Cleartext != "false" {
		t.Fatalf("base-config cleartextTrafficPermitted=%q, want false", cfg.Base.Cleartext)
	}

	seen, cleartext, anchored := map[string]bool{}, map[string]bool{}, map[string]bool{}
	pins := map[string][]string{}
	for _, dc := range cfg.DomainConfigs {
		if len(dc.Domains) == 0 {
			t.Fatal("a domain-config declares no domain")
		}
		if dc.Anchors != nil {
			if len(dc.Anchors.Certificates) != 1 || dc.Anchors.Certificates[0].Src != "@raw/tls_fixture_roots" {
				t.Fatalf("unexpected trust anchors: %+v", dc.Anchors.Certificates)
			}
		} else if len(dc.Pins) != 0 {
			t.Fatal("a pin-set without fixture anchors would pin the platform's own trust")
		}
		for _, d := range dc.Domains {
			if seen[d] {
				t.Fatalf("domain %q appears in two domain-configs; Android rejects that file", d)
			}
			seen[d] = true
			if dc.Cleartext == "true" {
				cleartext[d] = true
			}
			if dc.Anchors != nil {
				anchored[d] = true
			}
			for _, p := range dc.Pins {
				if p.Digest != "SHA-256" {
					t.Fatalf("%s: pin digest %q", d, p.Digest)
				}
				pins[d] = append(pins[d], p.Value)
			}
		}
	}

	// The debug build's own cleartext hosts, unchanged by the fixture manifest.
	sameSet(t, "cleartext hosts", cleartext, "localhost", "127.0.0.1", "::1", "10.0.2.2")
	// Fixture anchors reach loopback and the reserved names only; localhost, ::1 and
	// 10.0.2.2 carry no trust-anchors element, so they keep platform trust.
	sameSet(t, "anchored domains", anchored, "127.0.0.1", namedHost, pinnedHost)

	if got := pins[pinnedHost]; len(got) != 1 || got[0] != unmatchablePin {
		t.Fatalf("%s pins = %v, want the single unmatchable pin %q", pinnedHost, got, unmatchablePin)
	}
	digest, err := base64.StdEncoding.DecodeString(pins[pinnedHost][0])
	if err != nil || !bytes.Equal(digest, make([]byte, 32)) {
		t.Fatalf("the pin is not 32 zero bytes: %v %v", digest, err)
	}
	for d, got := range pins {
		if d != pinnedHost {
			t.Fatalf("domain %q carries pins %v; only %s may be pinned", d, got, pinnedHost)
		}
	}
}
