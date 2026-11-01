# KyAuth Visual Style Guide

## Brand

Use the Busnes.app-site KyPost mail stamp with the `KyAuth` wordmark in the header and lock screen. Keep the KyAuth launcher icon. Do not use `KyAuthenticator` in user-visible text.

## Themes

`ThemeManager.kt` is the Android copy of ky-ui 0.11.0 `THEME_PAIRS`. Six pairs, each with a light and a dark half:

- Busnes (Busnes Light, Busnes Dark)
- Matter (Matter Light, Matter Dark)
- Ocean (Ocean Light, Ocean Dark)
- Forest (Forest Light, Forest Dark)
- Ky (Ky Light, Ky Dark)
- Nord (Nord Light, Nord Dark)

Settings > Appearance has two rows: Theme (the pair) and Light or dark (System default, Light, Dark). The default is Busnes, System default. Use `ThemeManager.color` for app colors. Do not use fixed colors for a themed view.

Danger, warning and success come from the active half (`ky_danger`, `ky_warning`, `ky_success` and their `_soft` tints), never from the accent. Danger is a cool crimson. Show a state with `statusMessage`: its word, a dot and the soft tint. Never use colour alone.

## Layout

- Keep 20dp content padding at the screen edge.
- Add a larger header above dashboard content.
- Keep the three-part navigation pill at the bottom of the dashboard.
- Mark the active tab with an accent-soft pill and strong ink text, never accent text on accent-soft.
- Show a selected choice as an accent-soft tint with an accent bar at its start, not a heavy accent fill or outline.
- Put nothing under the brand: the wordmark stands alone and the page title follows as its own sentence.
- Group Settings content in padded cards.

## Shape and depth

- Use 14dp corners for inputs.
- Use 20dp corners for cards.
- Use 24dp corners for primary and secondary buttons.
- Use stadium corners for navigation pills and badges.
- Use flat custom controls. Do not use elevation shadows.

## Type and feedback

- Use system-scaled `sp` text sizes.
- Use monospace text only for codes, secrets, and technical values.
- Write labels, titles and captions in sentence case. No ALL-CAPS tracked labels.
- Keep button labels readable at large system font sizes.
- Mark copied OTP codes as sensitive and clear the app-owned clipboard entry on lock or expiry.

## Native behavior

Use Android system dialogs for biometric prompts. Use `AlertDialog` for confirmation and the About dialog. Apply the active theme palette to custom dialog content.
