package org.kysecurity.authenticator

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import android.content.res.Configuration
import androidx.core.graphics.ColorUtils
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ThemeManagerTest {
    @Test
    fun defaultsPreserveSavedChoicesAndBusnesTextHasContrast() {
        val context = withNight(false)
        val night = withNight(true)
        val prefs = context.getSharedPreferences("appearance", Context.MODE_PRIVATE)
        prefs.edit().clear().commit()
        try {
            assertEquals(ThemeManager.FOLLOW_PHONE, ThemeManager.currentName(context))
            assertEquals(0xfff8f6f0.toInt(), ThemeManager.color(context, R.color.ky_background))
            assertEquals(0xff182326.toInt(), ThemeManager.color(night, R.color.ky_background))
            ThemeManager.set(context, "Patina Ky")
            assertEquals("Patina Ky", ThemeManager.currentName(context))
            assertEquals(0xff0d0f14.toInt(), ThemeManager.color(context, R.color.ky_background))
            ThemeManager.set(context, ThemeManager.FOLLOW_PHONE)
            assertEquals(ThemeManager.FOLLOW_PHONE, ThemeManager.currentName(night))
            assertEquals(0xff182326.toInt(), ThemeManager.color(night, R.color.ky_background))
            ThemeManager.set(context, "unknown")
            assertEquals(ThemeManager.FOLLOW_PHONE, ThemeManager.currentName(context))
            for (name in listOf("Busnes Light", "Busnes Dark")) {
                ThemeManager.set(context, name)
                assertEquals(name, ThemeManager.currentName(context))
                for (surface in listOf(R.color.ky_background, R.color.ky_surface)) {
                    for (text in listOf(R.color.ky_text, R.color.ky_heading, R.color.ky_muted, R.color.ky_cyan)) {
                        assertTrue(ColorUtils.calculateContrast(
                            ThemeManager.color(context, text), ThemeManager.color(context, surface),
                        ) >= 4.5)
                    }
                }
                assertTrue(ColorUtils.calculateContrast(
                    ThemeManager.buttonText(context), ThemeManager.color(context, R.color.ky_cyan),
                ) >= 4.5)
            }
        } finally {
            prefs.edit().clear().commit()
        }
    }

    private fun withNight(night: Boolean): Context {
        val app = ApplicationProvider.getApplicationContext<Context>()
        val config = Configuration(app.resources.configuration).apply {
            uiMode = (uiMode and Configuration.UI_MODE_NIGHT_MASK.inv()) or
                if (night) Configuration.UI_MODE_NIGHT_YES else Configuration.UI_MODE_NIGHT_NO
        }
        return object : ContextWrapper(app.createConfigurationContext(config)) {
            override fun getSharedPreferences(name: String, mode: Int): SharedPreferences =
                super.getSharedPreferences("theme-test-$name", mode)
        }
    }
}
