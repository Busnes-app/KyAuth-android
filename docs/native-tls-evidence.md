# Android TLS key-floor investigation

## Measured baseline

Base source: `0f3fcc98abc9d78b38be452ba2acbee6c11f6d8d`. The unchanged
`pairing/ServerHttp.kt` was tested on an owned API 36 x86-64 emulator,
`google/sdk_gphone64_x86_64/emu64xa:16/BE2A.250530.026.F3/13894323:userdebug/dev-keys`.
The application used its ordinary Android trust manager and hostname verification,
with public fixture CAs selected only in an explicit debug-resource build.

| Peer | Before: TCP / HTTP / application bytes | Initial guard: TCP / HTTP / application bytes |
| --- | --- | --- |
| RSA-2047 | 1 / 1 / 26 | 1 / 0 / 0 |
| RSA-2048 | 1 / 1 / 26 | 1 / 1 / 26 |
| P-256 | 1 / 1 / 26 | 1 / 1 / 26 |

The host Go TLS calibration verifies the literal 2047-bit modulus and successful
normally trusted handshakes for all three peers. The unmodified native regression
fails on its HTTP assertion; the initial guard passes all three native assertions.
Values above are per-run counter deltas, so the baseline's successful requests are
not confused with the later guarded run. ADB instrumentation's process exit alone
is not a pass: its test summary and independent server counters determine the result.

## Expanded native measurements

The same API 36 runtime passed all four `ServerHttpTLSDeviceTest` methods against
30 calibrated cases. Each attempted TLS case reached its owned listener; refused
cases received zero HTTP requests and zero application bytes. Positive POST
controls received the 26-byte public canary. The final complete Play run, including
the system-anchor assertion and all available push transports, passed 40 tests
with zero failures or skips.

| Cases | Native result |
| --- | --- |
| RSA-1024 / RSA-2047 leaf, intermediate and off-wire root | Refused by the application key floor |
| Directly trusted non-CA self-signed RSA-1024 / RSA-2047 leaves | Refused by the application key floor |
| RSA-2048 leaf, strong three-level chain and directly trusted RSA-2048 leaf | Accepted |
| P-256 / P-384 | Accepted |
| P-521 / Ed25519 | Refused by the ordinary platform client as well as the guarded client |
| Wrong IP/DNS hostname, expired and untrusted certificate | Refused by native trust/hostname checks |
| Reserved DNS name with matching SAN | Accepted; peer observed the expected SNI |
| Matching name/chain with a deliberately wrong network-security-config pin | Native `Pin verification failed`, zero HTTP/bytes |
| TLS 1.0 / 1.1 | Ordinary and guarded clients both refused |
| TLS 1.2 / 1.3 | Accepted |
| HTTP 307 redirect | Returned to caller; target received no connection/request/bytes |

Android's actual returned path includes the selected anchor even when the peer
omits it; the test verifies its DER and the exact 2047-bit root modulus. Direct
trust cases are real singleton non-CA anchors, distinct from CA-signed leaves.
P-224 is certificate-only: the native parser exposes its 224-bit field and the
predicate refuses it, but the Go host cannot serve a P-224 TLS handshake. No
handshake refusal is claimed for that case. P-521 parsing produces a real 521-bit
`ECPublicKey`, which meets the predicate; platform handshake refusal is a separate
limitation. Ed25519 is outside this conservative policy.

The initial complete Play run failed two existing UI assertions despite all four
TLS methods passing. A captured System UI ANR dialog owned window focus, making
clipboard access fail; activity startup also exceeded the test's 2.5-second
challenge lifetime. Tests now await actual focus and start the short expiry after
launch. A failing full suite is never counted as a passing build.

The complete F-Droid run also succeeds: 37 executed tests pass and three FCM-only
workflows are excluded by explicit JUnit assumptions because that flavor has no
FCM transport. All four TLS methods run normally. Shared push-state regressions
exercise each available transport, including UnifiedPush. Android's raw XML
encodes those assumption exceptions in `failure` elements; the native runner and
Gradle classify them as exclusions. They are never counted as TLS passes.

An actual negative control replaced the evaluated path with the wire chain only.
The native test failed when `chain_root_rsa1024` received HTTP/application bytes:
the strong wire leaf/intermediate hid the omitted weak anchor. The original guard
was restored byte-for-byte. The unchanged-client RSA-2047 baseline above is the
independent control for omitting the guard entirely.

## Platform mechanism and scope

All five app-owned HTTP callers route through `ServerHttp`: pairing, sign-on token
redemption, MFA response, push credential refresh and device revocation. The new
factory is per HTTPS connection; it does not change the process-wide factories
used by Firebase, UnifiedPush, module downloads or the system browser.

The guard obtains Android's default `X509ExtendedTrustManager` from a null-store
`TrustManagerFactory`. It delegates the socket/engine trust check first, preserving
platform context. It then uses `X509TrustManagerExtensions` to obtain the validated
path including its selected anchor, and requires RSA at least 2048 actual bits or
EC fields at least 256 bits. Missing hostname, empty path, unrecognized key type or
unsupported platform manager fails closed. Native `HttpsURLConnection` hostname
verification, redirect refusal and request limits remain enabled. The additional
chain query is not a substitute for the initial context-aware platform check.

This is a conservative RSA/EC policy; the badge criterion's EC minimum is 224
bits, not 256. Generated application keys alone do not establish the separate
requirement that smaller accepted key lengths can be completely disabled: the
measured HTTPS peer is part of an application security mechanism.

## Primary sources

- [OpenSSF crypto_keylength](https://www.bestpractices.dev/en/criteria/0#crypto_keylength): defaults must meet the stated NIST minimums and smaller key lengths must be completely configurable off.
- [Conscrypt ChainStrengthAnalyzer](https://github.com/google/conscrypt/blob/master/common/src/main/java/org/conscrypt/ChainStrengthAnalyzer.java): the inspected source uses RSA 1024 / EC 160 minima. Recorded Git blob `68a5cf7fea3e07c0bdd050f870b18b6fcd32d002`.
- [Android RootTrustManager](https://github.com/aosp-mirror/platform_frameworks_base/blob/main/core/java/android/security/net/config/RootTrustManager.java): default network-security configuration, socket/engine handshake-host selection and hostname-aware chain return. Recorded blob `a1bdec5280db85aa543a0219f347efbf1fe86086`.
- [X509TrustManagerExtensions](https://github.com/aosp-mirror/platform_frameworks_base/blob/main/core/java/android/net/http/X509TrustManagerExtensions.java): returns the ordered trusted chain; this method alone is not hostname verification. Recorded blob `b44f75a585d5dd0455176f9991ed81887c42af8d`.
- [Android network security configuration](https://developer.android.com/privacy-and-security/security-config): app-specific trust settings and debug configuration.

The inspected moving source branches are identified by their recorded blob IDs;
they do not certify every vendor's current Conscrypt module. Native measurements
are limited to the emulator/version and fixture configuration named above. No
live server, physical device, broad OpenSSF answer or badge upgrade is claimed.

## Reviewed limits and rejected shortcuts

The platform's socket/engine check runs before the additional full-path query.
That query's public three-argument API does not receive TLS-delivered SCT/OCSP
inputs. With an explicitly CT-required configuration, a chain relying only on
TLS/OCSP-delivered SCTs may therefore be refused after platform validation. The
current release has no network-security configuration opting into CT; the
inspected AOSP default does not require CT. A CT-required deployment needs
separate qualification, including its SCT delivery, before claiming compatibility.
A private fixture CA cannot establish public-root CT enforcement, so no such
claim is made from these tests. No chain-query failure is ignored and no CT,
hostname or trust check is disabled to improve compatibility.

Native all-chain, DNS-name/SNI and pinning proof is preferred to mocking the
platform chain builder. The pure key predicate has JVM boundary tests; the
context-aware manager is exercised on the real Android runtime. CI's wrapper
checks the actual TLS test methods and fresh server counters. It requires the
RSA-2048 direct-trust control to carry HTTP, rather than crediting weak-key refusals
when a strong control also fails. The native test also checks the current default
system trust anchors against the floor, separately from fixture anchors.
Each run retains only its selected flavor's XML, its fresh logcat, counters and
gate verdict in its own fixture directory; stale/missing/skipped assertions cannot
produce a green transport gate. The Python gate's negative tests exercise absent,
skipped and stale XML, zero TCP, weak HTTP/bytes and a refused direct-trust control.
An aborted run with incomplete artifacts establishes no pass. Developers
may run ordinary device tests without fixture arguments; the strict wrapper is
required for TLS qualification. Those ordinary runs exclude the four TLS methods
through JUnit assumptions, which this Android reporter also encodes as `failure`
elements. A strict-wrapper run requires all four to execute successfully.

`Go 1.27.3` is a published tag (verified through the upstream Git tag API), not an
assumed version. Local fixture calibration currently uses Go 1.27.1-X:nodwarf5;
CI pins its own tool version and must pass calibration there independently.
