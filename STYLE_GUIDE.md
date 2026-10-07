# KyAuth Visual Style Guide

## Brand

Use the Busnes.app-site KyPost mail stamp with the `KyAuth` wordmark in the header and lock screen. Keep the KyAuth launcher icon. Do not use `KyAuthenticator` in user-visible text.

## Themes

`ThemeManager.kt` is the Android source of truth for these themes:

- Busnes Light
- Busnes Dark
- Dark Matter
- Light Matter
- Tropics
- Tropic Night
- Ocean
- Coffee
- White Cliffs
- Cyber Punk
- Neon Purple
- Space
- Sky
- Forest
- Sun
- Patina Ky
- Polished Ky

Busnes Light is the default when no valid theme is saved. Preserve existing saved choices. Use `ThemeManager.color` for app colors. Do not use fixed Patina colors for a themed view.

Keep danger and success colors separate from the theme palette.

## Layout

- Keep 20dp content padding at the screen edge.
- Add a larger header above dashboard content.
- Keep the three-part navigation pill at the bottom of the dashboard.
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
- Keep button labels readable at large system font sizes.
- Mark copied OTP codes as sensitive and clear the app-owned clipboard entry on lock or expiry.

## Native behavior

Use Android system dialogs for biometric prompts. Use `AlertDialog` for confirmation and the About dialog. Apply the active theme palette to custom dialog content.
