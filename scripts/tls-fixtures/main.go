// Command tls-fixtures runs owned loopback TLS peers and writes the public debug
// trust resources that select them. Private keys stay in memory; a trust anchor is
// published only as a public certificate. A CA anchor is never sent on the wire; a
// directly trusted case publishes the served end-entity leaf itself as its anchor.
//
// Most cases are reached as 127.0.0.1. The reserved .invalid cases are reached by name
// through the control CONNECT proxy, which forwards only the declared case host:port
// pairs to their owned loopback peers, so a device needs no DNS entry and no hosts file
// change while still doing its ordinary hostname, SNI and network-security-config work.
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// Case kinds, so a caller can tell an expected success from a measurement.
const (
	kindPositive        = "positive"         // must stay usable
	kindWeak            = "weak"             // below the key floor somewhere in the evaluated chain
	kindTrust           = "trust"            // ordinary trust, hostname or pinning failure
	kindPlatform        = "platform"         // native acceptance unknown; measure, do not assume
	kindRedirect        = "redirect"         // redirect source and its separate target
	kindCertificateOnly = "certificate-only" // real certificate, no peer: this host cannot serve it
)

// Flaws are mutually exclusive and apply to the leaf only.
const (
	flawUntrusted = "untrusted" // root withheld from the published anchors
	flawExpired   = "expired"
	flawWrongHost = "wrong-host"
)

// Reserved names. .invalid is guaranteed never to resolve (RFC 6761), so a case reached
// under one of these names can only have gone through the control CONNECT proxy.
const (
	namedHost    = "kyauth-tls-test.invalid"        // trusted anchors, no pin
	pinnedHost   = "pinned-kyauth-tls-test.invalid" // trusted anchors, deliberately wrong pin
	wrongHostSAN = "fixture.invalid"                // the only SAN of a wrong-host control
)

type spec struct {
	ID         string
	Kind       string
	Root       string // key spec of the issuing CA; empty only when Direct is set
	Inter      string // key spec of an intermediate; empty means the root signs the leaf
	Leaf       string
	Direct     bool   // leaf is self-signed, not a CA, and is itself the published anchor
	Host       string // reserved name this case is reached by; empty means 127.0.0.1
	Pinned     bool   // the generated config pins this case's name to a digest it cannot match
	Flaw       string
	Min, Max   uint16 // zero means TLS 1.2 through 1.3
	RedirectTo string // case ID of an owned target with its own counters
}

// A redirect source must follow its target so the target's port is already assigned.
var specs = []spec{
	// CA-signed leaves. A distinct disposable CA issues each leaf: the wire carries the
	// leaf alone, the CA is published as the anchor and stays off the wire, so the
	// evaluated path is two certificates even though only one is sent.
	{ID: "rsa1024", Kind: kindWeak, Root: "p256", Leaf: "rsa1024"},
	{ID: "rsa2047", Kind: kindWeak, Root: "p256", Leaf: "rsa2047"},
	{ID: "rsa2048", Kind: kindPositive, Root: "p256", Leaf: "rsa2048"},
	{ID: "p256", Kind: kindPositive, Root: "p256", Leaf: "p256"},
	{ID: "p384", Kind: kindPositive, Root: "p256", Leaf: "p384"},
	{ID: "p521", Kind: kindPlatform, Root: "p256", Leaf: "p521"},
	{ID: "ed25519", Kind: kindPlatform, Root: "p256", Leaf: "ed25519"},

	// Directly trusted end-entity leaves. No CA exists: the leaf signs itself, asserts
	// CA:FALSE, and is published as the anchor, so the same certificate is both on the
	// wire and in the trust store and the evaluated path is one certificate long.
	// trusted_rsa2048 is the strong control for the two below it: if it is refused too,
	// the platform rejects non-CA anchors outright and those refusals are not evidence
	// about the key floor.
	{ID: "trusted_rsa1024", Kind: kindWeak, Leaf: "rsa1024", Direct: true},
	{ID: "trusted_rsa2047", Kind: kindWeak, Leaf: "rsa2047", Direct: true},
	{ID: "trusted_rsa2048", Kind: kindPlatform, Leaf: "rsa2048", Direct: true},

	// Real three-level hierarchies. The wire carries leaf and intermediate; the anchor
	// is reachable only through the published trust store, so a chain check that stops
	// at the wire cannot see a weak root.
	{ID: "chain_strong", Kind: kindPositive, Root: "p256", Inter: "rsa2048", Leaf: "p256"},
	{ID: "chain_leaf_rsa1024", Kind: kindWeak, Root: "p256", Inter: "rsa2048", Leaf: "rsa1024"},
	{ID: "chain_leaf_rsa2047", Kind: kindWeak, Root: "p256", Inter: "rsa2048", Leaf: "rsa2047"},
	{ID: "chain_intermediate_rsa1024", Kind: kindWeak, Root: "p256", Inter: "rsa1024", Leaf: "rsa2048"},
	{ID: "chain_intermediate_rsa2047", Kind: kindWeak, Root: "p256", Inter: "rsa2047", Leaf: "rsa2048"},
	{ID: "chain_root_rsa1024", Kind: kindWeak, Root: "rsa1024", Inter: "rsa2048", Leaf: "rsa2048"},
	{ID: "chain_root_rsa2047", Kind: kindWeak, Root: "rsa2047", Inter: "rsa2048", Leaf: "rsa2048"},

	// Ordinary trust and hostname controls; every key here meets the floor.
	{ID: "invalid_hostname", Kind: kindTrust, Root: "p256", Leaf: "rsa2048", Flaw: flawWrongHost},
	{ID: "expired", Kind: kindTrust, Root: "p256", Leaf: "rsa2048", Flaw: flawExpired},
	{ID: "untrusted", Kind: kindTrust, Root: "p256", Leaf: "rsa2048", Flaw: flawUntrusted},

	// Reserved-name cases, reached by name through the control CONNECT proxy. They make
	// the name checks measurable: named differs from named_wrong_host only in the leaf's
	// DNS SAN, and pinned differs from named only in the generated pin-set.
	{ID: "named", Kind: kindPositive, Root: "p256", Leaf: "rsa2048", Host: namedHost},
	{ID: "named_wrong_host", Kind: kindTrust, Root: "p256", Leaf: "rsa2048", Host: namedHost, Flaw: flawWrongHost},
	{ID: "pinned", Kind: kindTrust, Root: "p256", Leaf: "rsa2048", Host: pinnedHost, Pinned: true},

	// Protocol versions, isolated by a strong trusted certificate.
	{ID: "tls10", Kind: kindPlatform, Root: "p256", Leaf: "rsa2048", Min: tls.VersionTLS10, Max: tls.VersionTLS10},
	{ID: "tls11", Kind: kindPlatform, Root: "p256", Leaf: "rsa2048", Min: tls.VersionTLS11, Max: tls.VersionTLS11},
	{ID: "tls12", Kind: kindPositive, Root: "p256", Leaf: "rsa2048", Min: tls.VersionTLS12, Max: tls.VersionTLS12},
	{ID: "tls13", Kind: kindPositive, Root: "p256", Leaf: "rsa2048", Min: tls.VersionTLS13, Max: tls.VersionTLS13},

	{ID: "redirect_target", Kind: kindRedirect, Root: "p256", Leaf: "rsa2048"},
	{ID: "redirect", Kind: kindRedirect, Root: "p256", Leaf: "rsa2048", RedirectTo: "redirect_target"},

	// crypto/tls refuses a P-224 server certificate, so this is a parsing control only.
	{ID: "p224", Kind: kindCertificateOnly, Root: "p256", Leaf: "p224"},
}

// TLS 1.0 and 1.1 have no AEAD suites, and Go's defaults are AEAD-only, so a genuine
// legacy peer has to name CBC-SHA suites explicitly.
var legacySuites = []uint16{
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
}

// namedHosts returns the distinct reserved names declared by the cases, in spec order.
func namedHosts(pinned bool) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range specs {
		if s.Host == "" || s.Pinned != pinned || seen[s.Host] {
			continue
		}
		seen[s.Host] = true
		out = append(out, s.Host)
	}
	return out
}

type countedListener struct {
	net.Listener
	accepted atomic.Int64
}

func (l *countedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return c, err
}

type peer struct {
	Port        int      `json:"port"`
	Host        string   `json:"host,omitempty"`         // reserved name to reach this case by; absent means 127.0.0.1
	Kind        string   `json:"kind"`                   //
	Chain       []string `json:"chain"`                  // base64 DER, leaf first, exactly what the peer sends
	Anchor      string   `json:"anchor,omitempty"`       // base64 DER; present iff published as a trust anchor
	DirectTrust bool     `json:"direct_trust,omitempty"` // the anchor is the served leaf, not a CA above it
	Pinned      bool     `json:"pinned,omitempty"`       // the generated config pins this name to an unmatchable digest
	TLSMin      string   `json:"tls_min,omitempty"`      // "1.0".."1.3"
	TLSMax      string   `json:"tls_max,omitempty"`      //
	RedirectTo  string   `json:"redirect_to,omitempty"`  // case ID this peer redirects to

	server     *http.Server
	listener   *countedListener
	requests   atomic.Int64
	bytes      atomic.Int64
	sni        atomic.Value // string: ServerName of the most recent ClientHello
	leaf       *x509.Certificate
	anchorCert *x509.Certificate // published as this case's trust anchor; the leaf itself when Direct
}

func (p *peer) stats() map[string]int64 {
	var connections int64
	if p.listener != nil {
		connections = p.listener.accepted.Load()
	}
	return map[string]int64{"connections": connections, "requests": p.requests.Load(), "bytes": p.bytes.Load()}
}

// observedSNI is the ServerName of the most recent ClientHello, empty when none arrived
// or when the client sent no SNI at all, as a client addressing an IP literal must not.
func (p *peer) observedSNI() string {
	name, _ := p.sni.Load().(string)
	return name
}

// handler counts every application byte that arrives. A redirect target, when given,
// is a separate owned peer that keeps its own counters.
func (p *peer) handler(target func() string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		if err != nil || len(body) > 4096 {
			http.Error(w, "invalid public probe", http.StatusBadRequest)
			return
		}
		p.requests.Add(1)
		p.bytes.Add(int64(len(body)))
		if target != nil {
			http.Redirect(w, r, target(), http.StatusTemporaryRedirect)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	})
}

type fixture struct {
	peers   map[string]*peer
	control *http.Server
	port    int
	anchors []byte
}

func newFixture() (*fixture, error) {
	f := &fixture{peers: map[string]*peer{}}
	for _, s := range specs {
		if err := f.add(s); err != nil {
			f.close()
			return nil, fmt.Errorf("case %s: %w", s.ID, err)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		f.close()
		return nil, err
	}
	f.port = ln.Addr().(*net.TCPAddr).Port
	f.control = &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(f.serveControl)}
	go f.control.Serve(ln)
	return f, nil
}

// serveControl is the loopback control plane: case metadata, counters, observed SNI, and
// the CONNECT proxy that reaches the reserved-name peers.
func (f *fixture) serveControl(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		f.connect(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/cases":
		json.NewEncoder(w).Encode(f.peers)
	case "/stats":
		stats := map[string]any{}
		for name, p := range f.peers {
			stats[name] = p.stats()
		}
		json.NewEncoder(w).Encode(stats)
	case "/sni":
		names := map[string]string{}
		for name, p := range f.peers {
			names[name] = p.observedSNI()
		}
		json.NewEncoder(w).Encode(names)
	default:
		http.NotFound(w, r)
	}
}

// proxyTarget maps a CONNECT destination to the owned loopback peer that declared it.
// It is an exact allowlist of declared case host:port pairs: everything else, including
// a bare loopback address and a declared name on another case's port, returns "".
func (f *fixture) proxyTarget(authority string) string {
	for _, p := range f.peers {
		if p.Host == "" {
			continue
		}
		port := strconv.Itoa(p.Port)
		if authority == net.JoinHostPort(p.Host, port) {
			return net.JoinHostPort("127.0.0.1", port)
		}
	}
	return ""
}

// connect tunnels to a declared reserved-name peer so the device reaches it by name with
// no DNS entry and no hosts file change. The tunnel carries the client's own TLS: the
// name, SNI and trust decisions all stay with the client. It is not a relay.
func (f *fixture) connect(w http.ResponseWriter, r *http.Request) {
	target := f.proxyTarget(r.Host)
	if target == "" {
		http.Error(w, "destination is not a declared fixture case", http.StatusForbidden)
		return
	}
	up, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		http.Error(w, "fixture peer unreachable", http.StatusBadGateway)
		return
	}
	defer up.Close()
	down, rw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "proxy needs a hijackable connection", http.StatusInternalServerError)
		return
	}
	defer down.Close()
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := rw.Flush(); err != nil {
		return
	}
	go func() {
		io.Copy(up, rw) // rw, not down: it may already hold pipelined bytes
		up.Close()
	}()
	io.Copy(down, up)
}

func (f *fixture) add(s spec) error {
	cert, anchor, err := build(s)
	if err != nil {
		return err
	}
	p := &peer{Kind: s.Kind, Host: s.Host, DirectTrust: s.Direct, Pinned: s.Pinned, RedirectTo: s.RedirectTo, leaf: cert.Leaf, anchorCert: anchor}
	for _, der := range cert.Certificate {
		p.Chain = append(p.Chain, base64.StdEncoding.EncodeToString(der))
	}
	if s.Flaw != flawUntrusted {
		p.Anchor = base64.StdEncoding.EncodeToString(anchor.Raw)
		f.anchors = append(f.anchors, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: anchor.Raw})...)
	}
	f.peers[s.ID] = p
	if s.Kind == kindCertificateOnly {
		return nil
	}

	min, max := s.Min, s.Max
	if min == 0 {
		min = tls.VersionTLS12
	}
	if max == 0 {
		max = tls.VersionTLS13
	}
	p.TLSMin, p.TLSMax = versionName(min), versionName(max)
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: min, MaxVersion: max}
	if min < tls.VersionTLS12 {
		cfg.CipherSuites = legacySuites
	}
	// Record the name the client actually asked for, then serve the config unchanged.
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		p.sni.Store(hello.ServerName)
		return nil, nil
	}

	var target func() string
	if s.RedirectTo != "" {
		t, ok := f.peers[s.RedirectTo]
		if !ok {
			return fmt.Errorf("redirect target %q must be defined first", s.RedirectTo)
		}
		target = func() string { return fmt.Sprintf("https://127.0.0.1:%d/probe", t.Port) }
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	p.listener = &countedListener{Listener: ln}
	p.Port = ln.Addr().(*net.TCPAddr).Port
	p.server = &http.Server{ReadHeaderTimeout: 5 * time.Second, ErrorLog: log.New(io.Discard, "", 0), Handler: p.handler(target)}
	go p.server.Serve(tls.NewListener(p.listener, cfg))
	return nil
}

func (f *fixture) close() {
	if f.control != nil {
		f.control.Close()
	}
	for _, p := range f.peers {
		if p.server != nil {
			p.server.Close()
		}
	}
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	}
	return ""
}

// newKey returns a disposable in-memory key. Nothing here is ever written to disk.
func newKey(spec string) (crypto.Signer, error) {
	switch spec {
	case "rsa1024":
		return rsa.GenerateKey(rand.Reader, 1024)
	case "rsa2047":
		return rsa.GenerateKey(rand.Reader, 2047)
	case "rsa2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "p224":
		return ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "p521":
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "ed25519":
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	}
	return nil, fmt.Errorf("unknown key spec %q", spec)
}

func issue(tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serial
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// build returns the peer certificate exactly as it goes on the wire, plus the certificate
// to publish as this case's trust anchor. For a CA-signed case that anchor is a distinct
// root which stays off the wire; for a directly trusted case it is the self-signed,
// explicitly non-CA leaf, which is therefore also the one certificate on the wire.
func build(s spec) (tls.Certificate, *x509.Certificate, error) {
	fail := func(err error) (tls.Certificate, *x509.Certificate, error) { return tls.Certificate{}, nil, err }
	now := time.Now()

	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "disposable KyAuth Android " + s.ID},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if s.Leaf == "rsa1024" || s.Leaf == "rsa2047" || s.Leaf == "rsa2048" {
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment // the legacy RSA key exchange needs it
	}
	// A reserved-name case is addressed by name only, so the IP SAN would hide a failed
	// name check behind the address the proxy happens to dial.
	if s.Host != "" {
		tmpl.IPAddresses, tmpl.DNSNames = nil, []string{s.Host}
	}
	switch s.Flaw {
	case flawExpired:
		tmpl.NotBefore, tmpl.NotAfter = now.Add(-48*time.Hour), now.Add(-24*time.Hour)
	case flawWrongHost:
		tmpl.IPAddresses, tmpl.DNSNames = nil, []string{wrongHostSAN}
	}
	leafKey, err := newKey(s.Leaf)
	if err != nil {
		return fail(err)
	}

	// Directly trusted: the leaf signs itself and is its own anchor. No CA is involved,
	// and CA:FALSE is asserted rather than merely absent.
	if s.Direct {
		if s.Root != "" || s.Inter != "" {
			return fail(fmt.Errorf("directly trusted case has no issuer, got root %q intermediate %q", s.Root, s.Inter))
		}
		tmpl.BasicConstraintsValid = true
		leaf, err := issue(tmpl, nil, leafKey.Public(), leafKey)
		if err != nil {
			return fail(err)
		}
		return tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: leafKey, Leaf: leaf}, leaf, nil
	}

	ca := func(name string) *x509.Certificate {
		return &x509.Certificate{
			Subject: pkix.Name{CommonName: "disposable KyAuth Android " + name},
			// Wide enough to also cover the expired control's backdated leaf, so that
			// control isolates leaf expiry and nothing else.
			NotBefore:             now.Add(-72 * time.Hour),
			NotAfter:              now.Add(24 * time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		}
	}
	rootKey, err := newKey(s.Root)
	if err != nil {
		return fail(err)
	}
	root, err := issue(ca(s.ID+" root"), nil, rootKey.Public(), rootKey)
	if err != nil {
		return fail(err)
	}
	issuer, issuerKey := root, rootKey
	var wire [][]byte
	if s.Inter != "" {
		interKey, err := newKey(s.Inter)
		if err != nil {
			return fail(err)
		}
		inter, err := issue(ca(s.ID+" intermediate"), root, interKey.Public(), rootKey)
		if err != nil {
			return fail(err)
		}
		issuer, issuerKey = inter, interKey
		wire = append(wire, inter.Raw)
	}
	leaf, err := issue(tmpl, issuer, leafKey.Public(), issuerKey)
	if err != nil {
		return fail(err)
	}
	return tls.Certificate{Certificate: append([][]byte{leaf.Raw}, wire...), PrivateKey: leafKey, Leaf: leaf}, root, nil
}

// The debug build's own cleartext hosts, restored here because the generated manifest
// replaces the debug one. 127.0.0.1 belongs to the anchored config below instead: a
// domain may appear in only one domain-config, and it keeps cleartext there, so the set
// is unchanged. These hosts get no trust-anchors element, so they keep platform trust.
var debugCleartextHosts = []string{"localhost", "::1", "10.0.2.2"}

// A SHA-256 pin of 32 zero bytes: no certificate can match it. The pinned case must fail
// pinning while its chain is otherwise trusted.
var unmatchablePin = base64.StdEncoding.EncodeToString(make([]byte, 32))

const (
	domainEntry    = `<domain includeSubdomains="false">%s</domain>`
	fixtureAnchors = `<trust-anchors><certificates src="@raw/tls_fixture_roots"/></trust-anchors>`
)

// networkSecurityConfig is the debug-only config the generated manifest selects. The
// fixture anchors reach loopback and the reserved fixture names and nothing else; the
// pinned name adds a pin it cannot match. overridePins is never set, so the platform
// enforces that pin against these anchors instead of waving it through.
func networkSecurityConfig() string {
	var b strings.Builder
	b.WriteString(`<network-security-config><base-config cleartextTrafficPermitted="false"/>`)
	b.WriteString(`<domain-config cleartextTrafficPermitted="true">`)
	for _, h := range debugCleartextHosts {
		fmt.Fprintf(&b, domainEntry, h)
	}
	b.WriteString(`</domain-config><domain-config cleartextTrafficPermitted="true">`)
	fmt.Fprintf(&b, domainEntry, "127.0.0.1")
	b.WriteString(fixtureAnchors + `</domain-config>`)
	// The reserved names are TLS-only: they exist to measure TLS, and nothing should be
	// able to answer them in cleartext.
	b.WriteString(`<domain-config>`)
	for _, h := range namedHosts(false) {
		fmt.Fprintf(&b, domainEntry, h)
	}
	b.WriteString(fixtureAnchors + `</domain-config>`)
	for _, h := range namedHosts(true) {
		b.WriteString(`<domain-config>`)
		fmt.Fprintf(&b, domainEntry, h)
		fmt.Fprintf(&b, `%s<pin-set><pin digest="SHA-256">%s</pin></pin-set></domain-config>`, fixtureAnchors, unmatchablePin)
	}
	b.WriteString(`</network-security-config>`)
	return b.String()
}

func (f *fixture) writeResources(out string) error {
	for _, name := range []string{"res/raw", "res/xml"} {
		if err := os.MkdirAll(filepath.Join(out, name), 0700); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(out, "res/raw/tls_fixture_roots.pem"), f.anchors, 0600); err != nil {
		return err
	}
	// This manifest is selected only through the explicit tlsFixtureDir debug property.
	manifest := `<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:networkSecurityConfig="@xml/tls_fixture_security" /></manifest>`
	for name, data := range map[string]string{"AndroidManifest.xml": manifest, "res/xml/tls_fixture_security.xml": networkSecurityConfig()} {
		if err := os.WriteFile(filepath.Join(out, name), []byte(data), 0600); err != nil {
			return err
		}
	}
	ready := map[string]any{"control_port": f.port, "cases": f.peers}
	data, err := json.Marshal(ready)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, "ready.json"), data, 0600)
}

func main() {
	out := flag.String("out", "", "owned output directory for public debug resources")
	flag.Parse()
	if *out == "" {
		log.Fatal("-out is required")
	}
	f, err := newFixture()
	if err != nil {
		log.Fatal(err)
	}
	defer f.close()
	if err = f.writeResources(*out); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("public fixture ready: %d cases, loopback control port %d\n", len(f.peers), f.port)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
}
