package org.kysecurity.authenticator

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.atan2
import kotlin.math.cbrt
import kotlin.math.cos
import kotlin.math.exp
import kotlin.math.hypot
import kotlin.math.pow
import kotlin.math.sin
import kotlin.math.sqrt

class ThemesTest {
    @Test
    fun sixPairsOfTwelveHalvesWithBusnesFirst() {
        assertEquals(listOf("Busnes", "Matter", "Ocean", "Forest", "Ky", "Nord"), Themes.pairs.map { it.name })
        assertEquals(12, Themes.halves.map { it.id }.toSet().size)
        Themes.pairs.forEach { assertTrue(!it.light.dark && it.dark.dark) }
        assertEquals(ThemeSelection("busnes-pair", ThemeMode.SYSTEM), Themes.DEFAULT)
    }

    @Test
    fun busnesHalvesMigrateWithTheirModeForced() {
        assertEquals(ThemeSelection("busnes-pair", ThemeMode.LIGHT), Themes.migrate("Busnes Light"))
        assertEquals(ThemeSelection("busnes-pair", ThemeMode.DARK), Themes.migrate("Busnes Dark"))
    }

    @Test
    fun survivingLegacyNamesMigrateToTheirHalf() {
        val expected = mapOf(
            "Dark Matter" to ThemeSelection("matter-pair", ThemeMode.DARK),
            "Light Matter" to ThemeSelection("matter-pair", ThemeMode.LIGHT),
            "Ocean" to ThemeSelection("ocean-pair", ThemeMode.DARK),
            "White Cliffs" to ThemeSelection("ocean-pair", ThemeMode.LIGHT),
            "Forest" to ThemeSelection("forest-pair", ThemeMode.DARK),
            "Patina Ky" to ThemeSelection("ky-pair", ThemeMode.DARK),
            "Polished Ky" to ThemeSelection("ky-pair", ThemeMode.LIGHT),
        )
        expected.forEach { (name, selection) -> assertEquals(name, selection, Themes.migrate(name)) }
    }

    @Test
    fun removedOrMissingChoicesResetToBusnesFollowingTheSystem() {
        listOf(null, "Follow phone", "Tropics", "Tropic Night", "Coffee", "Cyber Punk", "Neon Purple", "Space", "Sky", "Sun", "", "busnes-pair")
            .forEach { assertEquals("$it", Themes.DEFAULT, Themes.migrate(it)) }
    }

    @Test
    fun unknownSavedPairOrModeFallsBack() {
        assertEquals("busnes-pair", Themes.pair("tropics-pair").id)
        assertEquals(ThemeMode.SYSTEM, Themes.mode("sepia"))
    }

    @Test
    fun modeChoosesTheHalf() {
        val ky = ThemeSelection("ky-pair", ThemeMode.SYSTEM)
        assertEquals("polished-ky", Themes.resolve(ky, systemDark = false).id)
        assertEquals("patina-ky", Themes.resolve(ky, systemDark = true).id)
        assertEquals("patina-ky", Themes.resolve(ky.copy(mode = ThemeMode.DARK), systemDark = false).id)
        assertEquals("polished-ky", Themes.resolve(ky.copy(mode = ThemeMode.LIGHT), systemDark = true).id)
    }

    @Test
    fun softTintsMatchKyUiColorMix() {
        val busnes = Themes.pairs.first()
        assertEquals(0xfff5e3ea.toInt(), busnes.light.dangerSoft)
        assertEquals(0xff3a373e.toInt(), busnes.dark.dangerSoft)
    }

    @Test
    fun cieDe2000MatchesSharmaReferencePair() {
        // Sharma, Wu and Dalal (2005), table 1, pair 1.
        assertEquals(2.0425, ciede2000(doubleArrayOf(50.0, 2.6772, -79.7751), doubleArrayOf(50.0, 0.0, -82.7485)), 1e-4)
    }

    /** Port of ky-ui `scripts/check-status-colours.mjs`: 15 checks per half, 180 in all. */
    @Test
    fun statusColoursPassTheKyUiGate() {
        val failures = mutableListOf<String>()
        var checks = 0
        fun check(id: String, name: String, value: Double, min: Double) {
            checks++
            if (!(value >= min)) failures += "$id: $name ${"%.2f".format(value)} < $min"
        }
        for (half in Themes.halves) {
            val statuses = listOf(
                Triple("danger", half.danger, half.dangerSoft),
                Triple("warning", half.warning, half.warningSoft),
                Triple("success", half.success, half.successSoft),
            )
            for ((name, color, soft) in statuses) {
                check(half.id, "$name on bg", contrast(color, half.bg), 4.5)
                check(half.id, "$name on panel", contrast(color, half.panel), 4.5)
                check(half.id, "$name pill on $name-soft", contrast(color, soft), 4.5)
            }
            check(half.id, "ΔE accent–danger", deltaE(half.accent, half.danger), 20.0)
            val named = mapOf("accent" to half.accent, "danger" to half.danger, "warning" to half.warning, "success" to half.success)
            for ((a, b) in listOf("accent" to "warning", "accent" to "success", "danger" to "warning", "danger" to "success", "warning" to "success")) {
                check(half.id, "ΔE $a–$b", deltaE(named.getValue(a), named.getValue(b)), 10.0)
            }
        }
        assertEquals(180, checks)
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    @Test
    fun bodyTextAndButtonsAreReadable() {
        for (half in Themes.halves) {
            for (surface in listOf(half.bg, half.panel)) {
                assertTrue("${half.id} ink", contrast(half.ink, surface) >= 4.5)
                assertTrue("${half.id} inkStrong", contrast(half.inkStrong, surface) >= 4.5)
            }
            assertTrue("${half.id} button text", contrast(half.buttonText, half.accent) >= 4.5)
        }
    }

    private fun rgb(color: Int) = intArrayOf((color shr 16) and 0xff, (color shr 8) and 0xff, color and 0xff)

    private fun linear(v: Int): Double = (v / 255.0).let { if (it <= 0.04045) it / 12.92 else ((it + 0.055) / 1.055).pow(2.4) }

    private fun luminance(color: Int): Double = rgb(color).map(::linear).let { 0.2126 * it[0] + 0.7152 * it[1] + 0.0722 * it[2] }

    private fun contrast(a: Int, b: Int): Double {
        val (hi, lo) = listOf(luminance(a), luminance(b)).sortedDescending()
        return (hi + 0.05) / (lo + 0.05)
    }

    private fun lab(color: Int): DoubleArray {
        val (r, g, b) = rgb(color).map(::linear)
        val xyz = listOf(
            (0.4124564 * r + 0.3575761 * g + 0.1804375 * b) / 0.95047,
            0.2126729 * r + 0.7151522 * g + 0.072175 * b,
            (0.0193339 * r + 0.119192 * g + 0.9503041 * b) / 1.08883,
        ).map { t -> if (t > 216.0 / 24389) cbrt(t) else (24389.0 / 27 * t + 16) / 116 }
        return doubleArrayOf(116 * xyz[1] - 16, 500 * (xyz[0] - xyz[1]), 200 * (xyz[1] - xyz[2]))
    }

    private fun deltaE(a: Int, b: Int) = ciede2000(lab(a), lab(b))

    // Sharma, Wu and Dalal (2005), kL = kC = kH = 1; same steps as ky-ui.
    private fun ciede2000(x: DoubleArray, y: DoubleArray): Double {
        val (L1, a1, b1) = x.toList()
        val (L2, a2, b2) = y.toList()
        val rad = PI / 180
        val c = (hypot(a1, b1) + hypot(a2, b2)) / 2
        val g = 0.5 * (1 - sqrt(c.pow(7) / (c.pow(7) + 25.0.pow(7))))
        val ap1 = a1 * (1 + g)
        val ap2 = a2 * (1 + g)
        val cp1 = hypot(ap1, b1)
        val cp2 = hypot(ap2, b2)
        fun hue(b: Double, a: Double) = (atan2(b, a) / rad + 360) % 360
        val hp1 = hue(b1, ap1)
        val hp2 = hue(b2, ap2)
        val dL = L2 - L1
        val dC = cp2 - cp1
        var dh = if (cp1 * cp2 == 0.0) 0.0 else hp2 - hp1
        if (dh > 180) dh -= 360 else if (dh < -180) dh += 360
        val dH = 2 * sqrt(cp1 * cp2) * sin(dh * rad / 2)
        val lm = (L1 + L2) / 2
        val cm = (cp1 + cp2) / 2
        var hm = hp1 + hp2
        if (cp1 * cp2 != 0.0) hm = if (abs(hp1 - hp2) > 180) (hm + (if (hm < 360) 360 else -360)) / 2 else hm / 2
        val t = 1 - 0.17 * cos((hm - 30) * rad) + 0.24 * cos(2 * hm * rad) + 0.32 * cos((3 * hm + 6) * rad) - 0.2 * cos((4 * hm - 63) * rad)
        val sl = 1 + 0.015 * (lm - 50).pow(2) / sqrt(20 + (lm - 50).pow(2))
        val sc = 1 + 0.045 * cm
        val sh = 1 + 0.015 * cm * t
        val rt = -2 * sqrt(cm.pow(7) / (cm.pow(7) + 25.0.pow(7))) * sin(60 * exp(-((hm - 275) / 25).pow(2)) * rad)
        return sqrt((dL / sl).pow(2) + (dC / sc).pow(2) + (dH / sh).pow(2) + rt * (dC / sc) * (dH / sh))
    }
}
