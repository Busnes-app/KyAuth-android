# Native Android TLS fixtures

Owned loopback TLS peers plus the public debug trust resources that select them. They
exist to **measure** what Android's `ServerHttp` stack actually admits, before any
public fixture data reaches HTTP. Nothing here is shipped: release sources must never
contain the generated anchors.

## Running

```bash
go run . -out <directory>
```

`-out` is required and is written into, not read from. The process stays in the
foreground serving the peers until SIGINT/SIGTERM. It writes:

| Path | Contents |
| --- | --- |
| `res/raw/tls_fixture_roots.pem` | PEM `CERTIFICATE` blocks, one per published trust anchor |
| `res/xml/tls_fixture_security.xml` | network security config: see below |
| `AndroidManifest.xml` | selects that config; reached only through the `tlsFixtureDir` debug property |
| `ready.json` | `{"control_port": <int>, "cases": {<id>: <case>}}` |

Private keys are generated in memory per run and never written. Trust anchors are
written only as public certificates. A CA anchor is never sent on the wire; a directly
trusted case's anchor is the served leaf, so for those cases it is on the wire by
definition.

### Generated network security config

This file replaces the debug build's `debug_network_security.xml`, because the generated
manifest replaces the debug manifest. It therefore has to carry everything that one did:

- `base-config` forbids cleartext.
- The debug build's cleartext hosts are kept exactly: `localhost`, `127.0.0.1`, `::1`,
  `10.0.2.2`. Only `127.0.0.1` also gets the fixture anchors; `localhost`, `::1` and
  `10.0.2.2` carry no `trust-anchors` element at all and so keep **platform** trust.
- The fixture anchors reach `127.0.0.1` and the reserved fixture names and nothing else.
- The reserved names are TLS-only: no `cleartextTrafficPermitted` on them.
- The `pinned` name adds a `pin-set` holding one SHA-256 pin of 32 zero bytes, which no
  certificate can match. `overridePins` is never written anywhere in this file and
  `debug-overrides` is never used, so the platform **enforces** that pin against the
  fixture anchors rather than waving it through.
- Each domain appears in exactly one `domain-config`; Android rejects a file that repeats
  one, and `TestGeneratedNetworkSecurityConfig` asserts that on the written artifact.

## Control endpoints

Plain HTTP on `control_port`, loopback only.

- `GET /cases` → `{<id>: <case>}`, identical to `ready.json`'s `cases`.
- `GET /stats` → `{<id>: {"connections": n, "requests": n, "bytes": n}}` for every id,
  including certificate-only cases, which stay at zero. `connections` counts accepted
  TCP connections, `requests` counts HTTP requests that reached the handler, and
  `bytes` counts request-body bytes. A refusal that never reaches HTTP leaves
  `requests` and `bytes` at zero while `connections` may be non-zero.
- `GET /sni` → `{<id>: "<name>"}` for every id: the `ServerName` of the most recent
  ClientHello that peer saw, `""` when none arrived or when the client sent no SNI, as a
  client addressing an IP literal must not. It is captured before the handshake
  completes, so a client that aborts on a bad certificate still records its name.
- `CONNECT <host>:<port>` → tunnel, see below.
- Anything else → 404.

### CONNECT proxy

The control listener also answers `CONNECT`. It exists so a device can reach a case by a
name without a DNS entry, a hosts file edit or root. It is an **exact allowlist**: the
only destinations it accepts are the `host:port` pairs the reserved-name cases declare in
`/cases`, and each is forwarded to that case's own `127.0.0.1:<port>` listener. Everything
else — a declared name on another case's port, the same owned peer addressed as
`127.0.0.1`, the control port itself, any outside host — gets `403`.

The tunnel carries the client's own TLS end to end. The proxy terminates nothing, sees no
plaintext and injects no trust: the name in the URL, the SNI on the wire, the hostname
check and the network security config all stay with the client. On Android this is
reached by a **test-only** `ProxySelector`; production code and production trust are
unchanged.

### Case object

```json
{
  "port": 44295,
  "kind": "weak",
  "chain": ["<base64 DER leaf>", "<base64 DER intermediate>"],
  "anchor": "<base64 DER root>",
  "tls_min": "1.2",
  "tls_max": "1.3",
  "redirect_to": "redirect_target"
}
```

A reserved-name case adds the name it must be reached by, and the pinned one says so:

```json
{
  "port": 37595,
  "host": "pinned-kyauth-tls-test.invalid",
  "kind": "trust",
  "chain": ["<base64 DER leaf>"],
  "anchor": "<base64 DER root>",
  "pinned": true,
  "tls_min": "1.2",
  "tls_max": "1.3"
}
```

A directly trusted case instead carries one certificate that is also its own anchor:

```json
{
  "port": 39711,
  "kind": "weak",
  "chain": ["<base64 DER self-signed leaf>"],
  "anchor": "<the same base64 DER>",
  "direct_trust": true,
  "tls_min": "1.2",
  "tls_max": "1.3"
}
```

- `chain` is leaf-first and is byte-for-byte what the peer sends.
- `host` is the reserved name this case must be reached by, and is also its CONNECT
  destination host. **Absent means `127.0.0.1`** — the default, not a missing value.
- `pinned` is `true` **iff** the generated config pins this case's name to a digest no
  certificate can match. Absent otherwise.
- `direct_trust` is `true` **iff** this case's anchor is the served leaf itself — a
  self-signed, explicitly non-CA end-entity certificate, with no CA anywhere. Absent
  otherwise.
- `anchor` is present **iff** that certificate is in `tls_fixture_roots.pem`. The
  `untrusted` case omits it. Use it to assert where the platform-built path
  (`X509TrustManagerExtensions.checkServerTrusted`) ends. For a CA-signed case the anchor
  is **not** in `chain` and the built path is the wire chain plus exactly this
  certificate. For a `direct_trust` case the anchor **is** `chain[0]` and the built path
  is that single certificate.
- `tls_min`/`tls_max` are `"1.0"`–`"1.3"`, absent for certificate-only cases.
- `redirect_to` names another case id; absent otherwise.
- `port` is `0` exactly when `kind` is `certificate-only`.

### Kinds

| Kind | Meaning |
| --- | --- |
| `positive` | must stay usable; every key in the evaluated path meets RSA≥2048 / EC≥256 |
| `weak` | at least one certificate in the **evaluated path** (wire chain plus anchor) is below that floor |
| `trust` | ordinary trust or hostname failure; every key meets the floor |
| `platform` | native acceptance unknown — measure it, do not assume it |
| `redirect` | redirect source and its separate owned target |
| `certificate-only` | genuine certificate, no peer: this host cannot serve it |

## Cases

Every leaf has SAN `IP:127.0.0.1` unless noted.

CA-signed leaves — a distinct disposable CA issues the leaf, the wire carries the leaf
alone, and that CA is published as the anchor and stays off the wire. The evaluated path
is two certificates even though only one is sent:

| id | kind | leaf key |
| --- | --- | --- |
| `rsa1024` | weak | RSA 1024 |
| `rsa2047` | weak | RSA 2047 |
| `rsa2048` | positive | RSA 2048 |
| `p256` | positive | EC P-256 |
| `p384` | positive | EC P-384 |
| `p521` | platform | EC P-521 |
| `ed25519` | platform | Ed25519 |

Directly trusted end-entity leaves — no CA exists. The leaf signs itself, asserts
`CA:FALSE`, and is itself the published anchor, so the same certificate is both on the
wire and in the trust store and the evaluated path is one certificate long:

| id | kind | leaf key |
| --- | --- | --- |
| `trusted_rsa1024` | weak | RSA 1024 |
| `trusted_rsa2047` | weak | RSA 2047 |
| `trusted_rsa2048` | platform | RSA 2048 |

`trusted_rsa2048` is `platform`, not `positive`: every key in its path meets the floor,
but whether Android admits a non-CA trust anchor at all is unknown. It is the strong
control for the two above it — if `trusted_rsa2048` is refused as well, the platform
rejects non-CA anchors outright and the other two refusals say nothing about the key
floor.

Three-level hierarchies — wire carries leaf and intermediate, root reachable only
through the trust store. These are the all-evaluated-chain cases: a check that stops at
the wire cannot see `chain_root_*`.

| id | kind | root / intermediate / leaf |
| --- | --- | --- |
| `chain_strong` | positive | P-256 / RSA 2048 / P-256 |
| `chain_leaf_rsa1024` | weak | P-256 / RSA 2048 / RSA 1024 |
| `chain_leaf_rsa2047` | weak | P-256 / RSA 2048 / RSA 2047 |
| `chain_intermediate_rsa1024` | weak | P-256 / RSA 1024 / RSA 2048 |
| `chain_intermediate_rsa2047` | weak | P-256 / RSA 2047 / RSA 2048 |
| `chain_root_rsa1024` | weak | RSA 1024 / RSA 2048 / RSA 2048 |
| `chain_root_rsa2047` | weak | RSA 2047 / RSA 2048 / RSA 2048 |

Trust and hostname controls, all with RSA-2048 leaves so the key floor is not the variable:

| id | kind | flaw |
| --- | --- | --- |
| `invalid_hostname` | trust | only SAN is `DNS:fixture.invalid`; the client still dials `127.0.0.1` |
| `expired` | trust | leaf valid from −48 h to −24 h; its issuing CA covers that window |
| `untrusted` | trust | real root, withheld from `tls_fixture_roots.pem` |

Reserved-name cases, reached by `host` through the CONNECT proxy. All three are CA-signed
RSA-2048 leaves under published anchors, and none has an IP SAN — an IP SAN would let a
failed name check still succeed. So each differs from `named` in exactly one variable:

| id | kind | host | leaf DNS SAN | pinned |
| --- | --- | --- | --- | --- |
| `named` | positive | `kyauth-tls-test.invalid` | same, matches | no |
| `named_wrong_host` | trust | `kyauth-tls-test.invalid` | `fixture.invalid`, does not match | no |
| `pinned` | trust | `pinned-kyauth-tls-test.invalid` | same, matches | yes |

`named` and `named_wrong_host` sit under the same `domain-config` and the same anchors, so
the only thing separating them is the hostname check. `pinned` has a matching SAN and a
trusted chain, so the only thing left to refuse it is the pin.

Protocol versions, all RSA-2048 and trusted:

| id | kind | versions |
| --- | --- | --- |
| `tls10` | platform | 1.0 only |
| `tls11` | platform | 1.1 only |
| `tls12` | positive | 1.2 only |
| `tls13` | positive | 1.3 only |

Redirect and certificate-only:

| id | kind | note |
| --- | --- | --- |
| `redirect` | redirect | 307 to `https://127.0.0.1:<redirect_target port>/probe` |
| `redirect_target` | redirect | separate listener with its own counters |
| `p224` | certificate-only | EC P-224; no listener |

## Host calibration

`main_test.go` is the calibration. It proves each peer is a genuine, usable TLS endpoint
before any native refusal can be read as policy. It never uses `InsecureSkipVerify` and
never trusts everything: each client trusts that case's own root and nothing else.

- Negotiated version equals the case's `tls_max`.
- The wire chain matches the published `chain` byte-for-byte.
- Key algorithm and exact modulus bits / curve are asserted at leaf, intermediate and
  anchor — the literal 1024, 2047 and 2048 modulus bits, not a range.
- For a CA-signed case the anchor is a CA certificate, is absent from the wire chain, and
  the verified path is the wire chain plus exactly that certificate.
- For a `direct_trust` case the wire chain is a singleton equal to the published anchor,
  that certificate asserts `CA:FALSE`, and the verified path is it alone.
  `TestDirectlyTrustedLeaves` also verifies the leaf's signature with the leaf's own key,
  so "self-signed" is proven rather than assumed, and asserts that no other case claims
  `direct_trust`.
- `positive` cases have no certificate below the floor; `weak` cases have at least one.
- Counters advanced: `connections ≥ 1`, `requests == 1`, `bytes > 0`.
- `invalid_hostname` is calibrated under its real SAN `fixture.invalid` with a dialler
  that still reaches loopback, so only the name differs from the native attempt.
- `expired` is calibrated with a fixture-chosen `tls.Config.Time` at the midpoint of the
  leaf's validity. That time override belongs to host calibration only; the production
  client must never get one.
- `untrusted` is calibrated against its own withheld root, and a separate test asserts
  that root is absent from the published anchors.
- `redirect` is followed end to end and both counters are asserted independently.
- Every peer's observed SNI equals the name its calibration client dialled, and is empty
  for the loopback cases, so `/sni` is proven to report the real ClientHello and not a
  value the fixture made up.
- `named` and `pinned` are calibrated **through the CONNECT proxy**, under their reserved
  names, with ordinary verification. `TestControlProxyIsAnExactAllowlist` additionally
  verifies each declared tunnel destination and that every undeclared destination
  is refused with `403`. The transport explicitly selects the owned proxy; host DNS
  configuration is not part of the calibration.
- `named_wrong_host` is calibrated by direct dial under its real SAN `fixture.invalid`,
  the same way `invalid_hostname` is: the peer is proven sound, and only the name the
  device uses differs.
- `TestGeneratedNetworkSecurityConfig` parses the written XML and asserts the cleartext
  host set, the anchor scope, the single unmatchable pin and the absence of
  `overridePins` and `debug-overrides`.

Run it:

```bash
GODEBUG=fips140=off go test -race -count=1 ./...
```

## Host limitations, measured not assumed

- **P-224 cannot be served.** `x509.CreateCertificate` produces a valid P-224
  certificate, but `crypto/tls` refuses it as a server certificate with
  `tls: unsupported certificate curve (P-224)`. It is therefore a certificate-only
  control: `TestP224IsCertificateOnly` reproduces that exact error rather than inventing
  a TLS negative. A native predicate test can still parse the genuine certificate from
  `chain`.
- **Ed25519 can be served**, over TLS 1.3, so it is a real peer. Whether Android accepts
  it is unknown, hence `platform`.
- **TLS 1.0/1.1 are genuinely served.** Go 1.27 removed the `tls10server` GODEBUG, but an
  explicit `MinVersion`/`MaxVersion` plus an explicit CBC-SHA cipher list still works;
  Go's defaults are AEAD-only, which no TLS 1.0/1.1 suite is. Calibration negotiates
  `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`. A native failure against these peers may be a
  protocol refusal *or* the absence of a shared CBC-SHA suite; the two are not separable
  from the client side alone.
- **Host calibration cannot prove Android's non-CA trust admission.** Go accepts a self-signed end-entity
  certificate as a trust anchor and builds a one-certificate path for it; the `trusted_*`
  cases prove that on this host. Whether Android's `TrustManagerImpl` admits an anchor
  with `CA:FALSE` and no `keyCertSign` must be measured on the selected runtime.
  `trusted_rsa2048` stays `platform`, but the native gate requires its successful
  HTTP control before crediting weak direct-trust refusals. API 36 observations
  are recorded in `../../docs/native-tls-evidence.md`.
- **RSA 1024 and 2047 verify fine in Go** at leaf, intermediate and root. They do not
  verify fine everywhere: OpenSSL at its default security level rejects the RSA-1024
  `trusted_rsa1024` peer outright as `EE certificate key too weak` (verify code 66) while
  accepting `trusted_rsa2047`. That is an independent stack applying its own floor, not
  KyAuth's. Android may likewise refuse an RSA-1024 key or CA signature for a reason
  unrelated to KyAuth's floor, so treat the `*_rsa2047` variants as the primary evidence
  for the floor and the `*_rsa1024` variants as secondary.

- **A pin-set is not a host property.** No host client reads an Android network security
  config, so nothing here can prove the `pinned` case fails. The host proves the opposite
  half, which is the half that makes the native result readable: `pinned`'s chain
  verifies normally — Go's calibration accepts it, and `curl` with OpenSSL against the
  published anchors returns `{"ok":true}` over the proxy. Its chain, name and keys are
  therefore all sound, so a native refusal is attributable to the pin. If the device
  accepts it, pinning is not being enforced, and that is the finding.
- **Reserved names need no external DNS.** Calibration explicitly selects the owned
  CONNECT proxy and checks the observed TLS server name. It performs no resolver
  probe; local or corporate DNS behavior cannot turn that check into a flaky gate.
- **The proxy proves reachability, not trust.** It carries bytes. Every name check, SNI
  value, chain build and config decision in a native run is the device's own. A native
  pass obtained *by routing through the proxy* is still a real TLS pass; a native pass
  obtained by relaxing trust would not be, and nothing here relaxes trust.

## Rejected workarounds

- **Ignoring a full-chain query failure once the platform check has passed.** Rejected
  outright: the platform check and the key-floor check answer different questions, and
  swallowing the second one fails *open* for exactly the weak anchors the `chain_root_*`
  and `*_rsa2047` cases exist to catch. If the full chain cannot be obtained, that is a
  refusal, not a pass. Do not reintroduce it in any form.

## Scope

These peers measure one emulator or device at one API level. They certify no device, no
other API level and no live endpoint. Keep the negative and strong controls together: a
run where the strong controls also fail measured the harness, not the policy.
