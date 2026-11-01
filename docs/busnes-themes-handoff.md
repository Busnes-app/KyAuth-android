**Repo:** KyAuth-android

Superseded by the ky-ui 0.11.0 theme pairs (branch `design/ky-themes`). The 15 legacy palettes and
the separate Busnes Light and Busnes Dark entries are gone. `ThemeManager.kt` now holds six pairs
(Busnes, Matter, Ocean, Forest, Ky, Nord) with values copied from ky-ui `src/themes.js` and
`src/tokens.css`, a Light or dark mode (System default, Light, Dark), and per-half status colours.

Saved choices: the old `appearance` key `theme` is read once and replaced by `pair` and `mode`.
Busnes Light or Busnes Dark selects Busnes with that half forced; any other surviving half (Dark
Matter, Light Matter, Ocean, White Cliffs, Forest, Patina Ky, Polished Ky) selects its pair with
that half forced, as ky-ui does. Removed palettes (Tropics, Tropic Night, Coffee, Cyber Punk, Neon
Purple, Space, Sky, Sun), "Follow phone" and nothing saved become Busnes following the system.

Checks: `ThemesTest` (JVM) covers the migration and ports ky-ui `scripts/check-status-colours.mjs`
(180 checks across 12 halves). `ThemeManagerTest` (instrumented) covers the stored migration.
