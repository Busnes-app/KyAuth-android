**Repo:** kyauth-android
**Worktree:** /home/yoshi/busness.app/kyauth-android (branch main)

Added Busnes Light and Busnes Dark from ../busnes-color-theme-handoff.md. Busnes Light is the default/fallback; all 15 legacy palettes and valid saved selections remain. Added a heading token, readable accent labels, and system-bar icon contrast. Header/enrollment/lock-screen artwork now uses the exact ../Busnes.app-site/icons/kypost.png mail stamp as drawable-xxxhdpi/kypost_hero.png, explicitly confirmed by the user. KyAuth wordmark and launcher remain. Updated AGENTS.md and STYLE_GUIDE.md.

Validation: lintDebug and assembleDebug pass; text contrast checks pass (minimum 4.58:1 light, 4.90:1 dark). Full test and compileDebugAndroidTestSources are blocked by old SignOnPasskey* test references in the pre-existing, actively changing IdentityPasskey rename. Added ThemeManagerTest for defaults, saved choices, and palette contrast; it has not run on a device. One stale production string reference was updated to identity_passkey_restranded so the debug build succeeds.

Remaining: after the independent passkey rename finishes, rerun ./gradlew test lintDebug assembleDebug compileDebugAndroidTestSources; run ThemeManagerTest and visually inspect both palettes on a device. No install, commit, or deployment performed. Preserve the many unrelated dirty files and ongoing edits in this shared worktree.
