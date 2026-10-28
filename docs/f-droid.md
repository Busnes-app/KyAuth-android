# F-Droid

The listing (text, changelogs, icon, feature graphic, screenshots) is read from
`fastlane/metadata/android/en-US/`. Add `changelogs/<versionCode>.txt` with every release.

## Recipe for fdroiddata

Submit as `metadata/org.kysecurity.authenticator.yml` in a merge request to
<https://gitlab.com/fdroid/fdroiddata>.

```yaml
Categories:
  - Security
License: MIT
AuthorName: Busnes.app
WebSite: https://busnes.app
SourceCode: https://github.com/Busnes-app/KyAuth-android
IssueTracker: https://github.com/Busnes-app/KyAuth-android/issues

AutoName: KyAuth

RepoType: git
Repo: https://github.com/Busnes-app/KyAuth-android.git
Binaries: https://github.com/Busnes-app/KyAuth-android/releases/download/v%v/kyauth-v%v-fdroid.apk

Builds:
  - versionName: 0.5.0
    versionCode: 6
    commit: v0.5.0
    subdir: app
    gradle:
      - fdroid
  - versionName: 0.5.0.1
    versionCode: 7
    commit: v0.5.0.1
    subdir: app
    gradle:
      - fdroid

AllowedAPKSigningKeys: <signing certificate SHA-256 from the GitHub release notes, lowercase>

AutoUpdateMode: Version
UpdateCheckMode: Tags
CurrentVersion: 0.5.0.1
CurrentVersionCode: 7
```

`Binaries` with `AllowedAPKSigningKeys` asks F-Droid to rebuild from source, check the result
matches the APK the release workflow published, and ship ours. F-Droid users then hold the same
signature as GitHub users and can move between the two without reinstalling.

## Open before submitting

- **JDK 25.** The Gradle daemon needs JDK 25 (`gradle/gradle-daemon-jvm.properties`) and
  downloads it from foojay when none is installed. F-Droid's build server may block that; the
  recipe may need a `sudo:` step installing JDK 25. Unproven.
- **Reproducibility across machines.** Proven only between two local checkouts; F-Droid's
  server is the real test. If it fails, drop `Binaries` and `AllowedAPKSigningKeys` and F-Droid
  signs with its own key.
