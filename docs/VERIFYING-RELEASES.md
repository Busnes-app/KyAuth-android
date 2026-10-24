# Verifying releases

[Product overview](../README.md) · [Security](../SECURITY.md) · [F-Droid](f-droid.md)

A KyAuth GitHub release carries two APKs, `kyauth-vX.Y.Z-github.apk` and
`kyauth-vX.Y.Z-fdroid.apk`, and a `SHA256SUMS` file. This page shows how to check that an APK was
signed with KyAuth's release key, that this repository's release workflow built it from the tagged
commit, and how to rebuild it from source and compare.

## What is signed, and by whom

- **The APK signature.** `release.yml` signs both APKs with the KyAuth release key (APK Signature
  Scheme v2). Android checks this signature on install and refuses an update signed by a different
  key. The certificate is:

  | | |
  |---|---|
  | Subject | `CN=KyAuth Release, OU=KySecurity, O=KySecurity, C=US` |
  | SHA-256 | `52f61684029401fcb0137b334ad41907f83948fa1ec1377834f3b4291765fd7b` |

  Each release's notes repeat this digest. If the notes and this page ever disagree, do not install
  the APK; report it as described in [SECURITY.md](../SECURITY.md).
- **Build provenance.** The same workflow publishes a SLSA build-provenance attestation for each
  APK through GitHub's Sigstore integration. There is no long-lived key to download. The
  attestation is tied to a workflow identity, and that identity is what you check:
  `https://github.com/Busnes-app/KyAuth-android/.github/workflows/release.yml@refs/tags/v<version>`.
- **`SHA256SUMS`** is not signed or attested. It catches a damaged download. The signature and the
  attestation are what prove where the APK came from.
- **Google Play builds** are re-signed by Google under Play App Signing and carry a different
  certificate. Nothing on this page applies to them; Play verifies its own installs.

## Verify a downloaded APK

You need `gh` (logged in) and `apksigner`, which is in the Android SDK's `build-tools` directory.
Name the version yourself.

```bash
v=<release version, e.g. 0.5.0>
gh release download v$v -R Busnes-app/KyAuth-android && sha256sum -c SHA256SUMS

# 1. Signed with the KyAuth release key. Must print the SHA-256 above, once per APK.
for apk in kyauth-v$v-github.apk kyauth-v$v-fdroid.apk; do
  apksigner verify --print-certs "$apk" | grep 'certificate SHA-256 digest'
done

# 2. Built by release.yml at tag v$v, from the commit that tag points at.
sha=$(gh api repos/Busnes-app/KyAuth-android/commits/refs/tags/v$v --jq .sha)
for apk in kyauth-v$v-github.apk kyauth-v$v-fdroid.apk; do
  [ "$(gh attestation verify "$apk" --repo Busnes-app/KyAuth-android \
       --cert-identity https://github.com/Busnes-app/KyAuth-android/.github/workflows/release.yml@refs/tags/v$v \
       --format json --jq '.[0].verificationResult.statement.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit')" = "$sha" ] \
    && echo "OK: $apk is release v$v, built from $sha" || echo "FAIL: $apk"
done
```

Any failure means: do not install that APK. A different workflow, a branch instead of the tag, or
another repository all fail the `--cert-identity` or `--repo` check.

`apksigner verify` with no options exits non-zero on a bad signature. `keytool -printcert -jarfile`
does **not** work here: KyAuth APKs carry only a v2 signature, so keytool answers "Not a signed jar
file".

## Rebuild the APK and compare

The F-Droid recipe in [f-droid.md](f-droid.md) depends on a rebuild matching the published APK, so
this is the check F-Droid itself runs. You need the Android SDK and any JDK 17 or newer; Gradle
provisions JDK 25 for its daemon. Clone the tag rather than downloading a source archive: the
Android Gradle plugin records the commit in `META-INF/version-control-info.textproto`, and without
`.git` it records an error there instead.

```bash
v=<release version>
git clone --branch v$v https://github.com/Busnes-app/KyAuth-android.git kyauth-v$v && cd kyauth-v$v
./gradlew assembleFdroidRelease      # no signing secrets set, so the APK is unsigned
cd .. && mkdir built published
unzip -q -d built kyauth-v$v/app/build/outputs/apk/fdroid/release/app-fdroid-release-unsigned.apk
unzip -q -d published kyauth-v$v-fdroid.apk
diff -r built published && echo "identical contents"
```

On some systems `diff` reports exactly two files, `assets/dexopt/baseline.prof` and
`baseline.profm`. The v0.5.0 results below explain why that is not a difference in the code.

The unsigned build has no signature block, so compare what is inside the two APKs, not the two
files. F-Droid does the same comparison with `apksigcopier`, which copies the published signature
onto the rebuilt APK and requires the result to verify.

What was checked for v0.5.0 (commit `c6adfb5`): a build on Fedora matched the published fdroid APK
in 1025 of its 1027 entries, including every `classes.dex`, resource and native library. The two
that differed were `assets/dexopt/baseline.prof` and `baseline.profm`. Each holds a
zlib-compressed ART profile, and after decompression both were byte-identical to the published
ones. Only the compressed bytes differ. The likely cause is the compressor: the JDK on that
machine uses Fedora's system zlib, which is zlib-ng, and the release runner is Ubuntu. That cause
has not been proven. Two builds on the same machine, from different directories and with 20 and
4 CPUs, were identical in every entry. The github flavor was not rebuilt.

## What this does not prove

- That the source at the tag is safe. It proves the APK came from it.
- Anything about a Play install. Google signs those.
- That a rebuild on another system matches outright. On a Debian or Ubuntu system the baseline
  profiles are expected to match too, but only the result above has been observed.
