package org.kysecurity.authenticator

import android.content.Context
import androidx.core.content.ContextCompat
import androidx.core.content.edit

/** One half of a pair. Colours are ARGB. Values match ky-ui 0.11.0 `src/themes.js` and `src/tokens.css`. */
internal data class ThemeHalf(
    val id: String,
    val name: String,
    val dark: Boolean,
    val bg: Int,
    val panel: Int,
    val ink: Int,
    val inkStrong: Int,
    val accent: Int,
    val accentSoft: Int,
    val line: Int,
    val buttonText: Int,
    val danger: Int,
    val warning: Int,
    val success: Int,
    /** Names KyAuth saved before the pairs, and ky-ui's aliases. */
    val aliases: List<String> = emptyList(),
) {
    val dangerSoft get() = Themes.mix(danger, Themes.SOFT_PERCENT, panel)
    val warningSoft get() = Themes.mix(warning, Themes.SOFT_PERCENT, panel)
    val successSoft get() = Themes.mix(success, Themes.SOFT_PERCENT, panel)
}

internal data class ThemePair(val id: String, val name: String, val light: ThemeHalf, val dark: ThemeHalf)

enum class ThemeMode(val id: String, val label: String) {
    SYSTEM("system", "System default"),
    LIGHT("light", "Light"),
    DARK("dark", "Dark"),
}

internal data class ThemeSelection(val pairId: String, val mode: ThemeMode)

/** The six suite pairs and the rules for saved choices. No Android types, so JVM tests can run it. */
internal object Themes {
    const val SOFT_PERCENT = 12

    private fun c(hex: String): Int = java.lang.Long.parseLong(hex.removePrefix("#").let { if (it.length == 6) "ff$it" else it }, 16).toInt()

    // Shared status defaults per scheme (tokens.css). Danger is a cool crimson, never the accent.
    private const val DANGER_LIGHT = "#a8174e"
    private const val DANGER_DARK = "#ff8fb1"
    private const val WARNING_LIGHT = "#7a5f00"
    private const val WARNING_DARK = "#ffd25e"
    private const val SUCCESS_LIGHT = "#267442"
    private const val SUCCESS_DARK = "#86efac"

    private fun half(
        id: String, name: String, dark: Boolean,
        bg: String, panel: String, ink: String, inkStrong: String, accent: String, accentSoft: String, line: String, buttonText: String,
        aliases: List<String> = emptyList(), danger: String? = null, success: String? = null,
    ) = ThemeHalf(
        id, name, dark, c(bg), c(panel), c(ink), c(inkStrong), c(accent), c(accentSoft), c(line), c(buttonText),
        c(danger ?: if (dark) DANGER_DARK else DANGER_LIGHT),
        c(if (dark) WARNING_DARK else WARNING_LIGHT),
        c(success ?: if (dark) SUCCESS_DARK else SUCCESS_LIGHT),
        aliases,
    )

    // Busnes lines are translucent ink (#AARRGGBB). Nord's accent-soft is rgba(136,192,208,.2) flattened onto its panel.
    // Forest's success is teal, because the shared green sits too close to its green accent.
    val pairs = listOf(
        ThemePair(
            "busnes-pair", "Busnes",
            half("busnes-light", "Busnes Light", false, "#f8f6f0", "#ffffff", "#566461", "#182326", "#bf3f18", "#fbf0ec", "#38182326", "#ffffff"),
            half("busnes-dark", "Busnes Dark", true, "#182326", "#1f2b2e", "#b3bcb8", "#f2efe8", "#f5865f", "#2b2622", "#3df2efe8", "#182326"),
        ),
        ThemePair(
            "matter-pair", "Matter",
            half("light-matter", "Matter Light", false, "#f5efe5", "#fff8ee", "#4c3d32", "#2d1f15", "#805a39", "#e2d0b8", "#d4c7b5", "#ffffff", listOf("Light Matter")),
            half("dark-matter", "Matter Dark", true, "#1d1b19", "#292725", "#cfc6bb", "#f0e9df", "#c29a72", "#49392c", "#45403a", "#24170f", listOf("Dark Matter", "Current")),
        ),
        ThemePair(
            "ocean-pair", "Ocean",
            half("white-cliffs", "Ocean Light", false, "#f7f9fb", "#ffffff", "#2e4c63", "#163246", "#1d5fa6", "#dde9f7", "#c7d6df", "#ffffff", listOf("White Cliffs", "Cliffs")),
            half("ocean", "Ocean Dark", true, "#0f1b24", "#152a36", "#b8d8e8", "#e0f2fb", "#6aa8e8", "#1f3a55", "#2f5567", "#0a1b22", listOf("Ocean")),
        ),
        ThemePair(
            "forest-pair", "Forest",
            half("forest-light", "Forest Light", false, "#f3f6ef", "#fcfdf9", "#435342", "#203322", "#4b6b37", "#e2ebda", "#c5d0bc", "#ffffff", success = "#00737a"),
            half("forest", "Forest Dark", true, "#142018", "#1f2f24", "#c7dbc7", "#e3f0df", "#8faa74", "#3a5837", "#4f694f", "#12200f", listOf("Forest"), success = "#6ee0d0"),
        ),
        ThemePair(
            "ky-pair", "Ky",
            half("polished-ky", "Ky Light", false, "#eef2f6", "#ffffff", "#475569", "#0f172a", "#08758b", "#daf2f4", "#c2cdd8", "#ffffff", listOf("Polished Ky")),
            half("patina-ky", "Ky Dark", true, "#10161e", "#1b2530", "#afbdca", "#e2e8f0", "#6fc9cc", "#203d41", "#34414d", "#10161e", listOf("Patina Ky", "patina", "Patina Ky (base)")),
        ),
        ThemePair(
            "nord-pair", "Nord",
            half("paper", "Nord Light", false, "#eceff4", "#ffffff", "#4c566a", "#2e3440", "#4a6a94", "#dbe4ef", "#c5cdd9", "#ffffff", listOf("Paper Clean")),
            half("nord", "Nord Dark", true, "#2e3440", "#3b4252", "#d8dee9", "#eceff4", "#88c0d0", "#4a5b6b", "#4c566a", "#0d0f14", listOf("Nord", "Nord Slate"), danger = "#ecc4c8", success = "#bcd4aa"),
        ),
    )

    val halves get() = pairs.flatMap { listOf(it.light, it.dark) }

    val DEFAULT = ThemeSelection("busnes-pair", ThemeMode.SYSTEM)

    fun pair(id: String?): ThemePair = pairs.firstOrNull { it.id == id } ?: pairs.first()

    fun mode(id: String?): ThemeMode = ThemeMode.entries.firstOrNull { it.id == id } ?: ThemeMode.SYSTEM

    fun resolve(selection: ThemeSelection, systemDark: Boolean): ThemeHalf {
        val pair = pair(selection.pairId)
        val dark = when (selection.mode) {
            ThemeMode.SYSTEM -> systemDark
            ThemeMode.LIGHT -> false
            ThemeMode.DARK -> true
        }
        return if (dark) pair.dark else pair.light
    }

    /**
     * Maps a theme name saved before the pairs. A half that still exists (Busnes Light, Ocean,
     * Patina Ky, ...) selects its pair with that half forced, because the user chose the mode by
     * choosing it. A removed palette (Tropics, Coffee, Sky, ...), "Follow phone" or nothing
     * resets to Busnes following the system.
     */
    fun migrate(legacyName: String?): ThemeSelection {
        if (legacyName == null) return DEFAULT
        for (pair in pairs) {
            for (half in listOf(pair.light, pair.dark)) {
                if (legacyName == half.id || legacyName == half.name || legacyName in half.aliases) {
                    return ThemeSelection(pair.id, if (half.dark) ThemeMode.DARK else ThemeMode.LIGHT)
                }
            }
        }
        return DEFAULT
    }

    /** CSS `color-mix(in srgb, a p%, b)` on opaque colours, as ky-ui's soft tints use. */
    fun mix(a: Int, percent: Int, b: Int): Int {
        fun ch(color: Int, shift: Int) = (color shr shift) and 0xff
        fun blend(shift: Int) = Math.round(ch(a, shift) * percent / 100.0 + ch(b, shift) * (1 - percent / 100.0)).toInt()
        return (0xff shl 24) or (blend(16) shl 16) or (blend(8) shl 8) or blend(0)
    }
}

object ThemeManager {
    private const val PREFS = "appearance"
    private const val KEY_PAIR = "pair"
    private const val KEY_MODE = "mode"
    // Before the pairs, KyAuth saved one palette name here.
    private const val KEY_LEGACY_THEME = "theme"

    fun pairNames(): List<String> = Themes.pairs.map { it.name }

    fun pairName(context: Context): String = Themes.pair(selection(context).pairId).name

    fun mode(context: Context): ThemeMode = selection(context).mode

    fun setPair(context: Context, name: String) {
        val pair = Themes.pairs.firstOrNull { it.name == name } ?: return
        prefs(context).edit { putString(KEY_PAIR, pair.id) }
    }

    fun setMode(context: Context, mode: ThemeMode) {
        prefs(context).edit { putString(KEY_MODE, mode.id) }
    }

    /** Light and dark preview colours (bg, accent) for each pair, in [pairNames] order. */
    internal fun pairPreviews(): List<Pair<ThemeHalf, ThemeHalf>> = Themes.pairs.map { it.light to it.dark }

    fun color(context: Context, colorRes: Int): Int {
        val theme = current(context)
        return when (colorRes) {
            R.color.ky_background -> theme.bg
            R.color.ky_surface, R.color.ky_surface_elevated -> theme.panel
            R.color.ky_text, R.color.ky_muted -> theme.ink
            R.color.ky_heading -> theme.inkStrong
            R.color.ky_cyan -> theme.accent
            R.color.ky_cyan_dim -> theme.accentSoft
            R.color.ky_border -> theme.line
            R.color.ky_danger -> theme.danger
            R.color.ky_danger_soft -> theme.dangerSoft
            R.color.ky_warning -> theme.warning
            R.color.ky_warning_soft -> theme.warningSoft
            R.color.ky_success -> theme.success
            R.color.ky_success_soft -> theme.successSoft
            else -> ContextCompat.getColor(context, colorRes)
        }
    }

    fun buttonText(context: Context): Int = current(context).buttonText

    private fun prefs(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Reads the saved pair and mode, converting a pre-pairs saved name once. */
    private fun selection(context: Context): ThemeSelection {
        val prefs = prefs(context)
        if (prefs.contains(KEY_LEGACY_THEME)) {
            val migrated = Themes.migrate(prefs.getString(KEY_LEGACY_THEME, null))
            prefs.edit {
                remove(KEY_LEGACY_THEME)
                putString(KEY_PAIR, migrated.pairId)
                putString(KEY_MODE, migrated.mode.id)
            }
            return migrated
        }
        return ThemeSelection(Themes.pair(prefs.getString(KEY_PAIR, null)).id, Themes.mode(prefs.getString(KEY_MODE, null)))
    }

    private fun current(context: Context): ThemeHalf =
        Themes.resolve(selection(context), context.resources.configuration.isNightModeActive)
}
