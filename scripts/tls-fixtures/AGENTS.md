# Native Android TLS fixtures

## Purpose

Measure actual Android ServerHttp TLS admission before public fixture data reaches HTTP.

## Ownership

Standard-library Go loopback peers and generated debug-only trust resources. The root owns Android instrumentation, Gradle wiring and CI.

`README.md` holds the case table, the control-endpoint schema and the measured host limitations. Update it in the same change as `main.go`.

## Local Contracts

- Generate disposable keys in memory; persist only public trust anchors and test metadata.
- Bind owned loopback listeners and distinguish TCP connections from HTTP requests/bytes.
- Use ordinary Android trust and hostname checks with explicitly selected debug fixture anchors; release resources never include them.
- Calibrate every peer with a real host TLS client before interpreting native refusal. Never `InsecureSkipVerify` and never a trust-all client: each calibration trusts that case's own published anchor alone -- its issuing CA, or the leaf itself for a `direct_trust` case.
- The expired control's time override belongs to host calibration only. The production client never gets one.
- Keep negative and strong controls; native observations do not certify every device or a live endpoint.
- `-out` writes `res/raw/tls_fixture_roots.pem`, `res/xml/tls_fixture_security.xml`, `AndroidManifest.xml` and `ready.json` (`{control_port, cases}`). `/cases` returns `{id: {port, host?, kind, chain, anchor?, direct_trust?, pinned?, tls_min?, tls_max?, redirect_to?}}`; `/stats` returns `{id: {connections, requests, bytes}}` for every id and its numeric schema is frozen; `/sni` returns `{id: lastObservedServerName}` for every id. These are a wire contract with the Android test: add fields, do not rename or drop them.
- `host` is absent for a loopback case and the consumer defaults it to `127.0.0.1`. A case that declares `host` has no IP SAN, so it can only be reached by that name.
- The control listener is also a CONNECT proxy, and it is an exact allowlist of the declared `host:port` pairs forwarded to their own loopback peers; everything else is `403`. It must stay a tunnel: no termination, no injected trust, no second destination. The device side is a test-only `ProxySelector`, never a production proxy and never a trust override.
- The generated network security config replaces the debug one, so it must keep the debug cleartext hosts `localhost`, `127.0.0.1`, `::1`, `10.0.2.2`. Only `127.0.0.1` and the reserved names get `trust-anchors`; the other three keep platform trust. Each domain appears in exactly one `domain-config` or Android rejects the file.
- The `pinned` name carries one SHA-256 pin of 32 zero bytes. Never write `overridePins` and never use `debug-overrides`: either one would make the pin unenforced and the case meaningless.
- Nothing on this host can prove a pin fails -- no host client reads a network security config. Calibrate `pinned` as a sound chain so the native refusal is attributable, and say "unproven" about the pin itself.
- `chain` is leaf-first base64 DER and is exactly what the peer sends. `anchor` is present iff that certificate is published, so the `untrusted` control omits it.
- Two distinct trust shapes, and the difference is load-bearing. A CA-signed case has a distinct issuing CA as its anchor: that anchor is never on the wire and the evaluated path is the wire chain plus one. A `direct_trust` case has no CA at all: the leaf is self-signed, asserts `CA:FALSE`, and is itself the published anchor, so it is on the wire, the wire chain is a singleton and the evaluated path is one certificate. The anchor-never-on-the-wire invariant applies only to the CA-signed hierarchies; do not state it unconditionally.
- Case ids `rsa2047`, `rsa2048`, `p256`, `trusted_rsa1024`, `trusted_rsa2047` and `trusted_rsa2048` are referenced by name and must keep their meaning. The `rsa*` and `p*` single-certificate cases are CA-signed leaves, not directly trusted ones; only the `trusted_*` cases are directly trusted.
- `trusted_rsa2048` is the measured runtime's strong control for `trusted_rsa1024`/`trusted_rsa2047`. Its `platform` classification does not permit a passing native gate when it refuses: the gate requires actual HTTP so weak direct-trust refusals establish a key-floor result.
- `kind` is one of `positive`, `weak`, `trust`, `platform`, `redirect`, `certificate-only`. A key size or protocol version whose native acceptance is unknown is `platform`, never `positive`.
- Do not invent a TLS negative this host cannot serve. When Go refuses to serve a key, keep the case as `certificate-only` and reproduce the exact host error in a test.
- Reserved `.invalid` names use an explicitly selected CONNECT proxy; verify its observed SNI. The fixture needs no DNS queries, hosts-file edits or root access.
- Never ignore a failed full-chain query after a platform check passes. The two answer different questions and swallowing the second fails open for weak anchors, which is precisely what the `chain_root_*` cases exist to catch. A chain that cannot be obtained is a refusal.

## Work Guidance

Use Go's standard library and keep the fixture independent of application dependencies.

## Verification

`GODEBUG=fips140=off go test -race -count=1 ./...` from this directory.

## Child DOX Index

None.
