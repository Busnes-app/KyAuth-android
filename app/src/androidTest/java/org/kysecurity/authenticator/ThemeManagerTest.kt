package org.kysecurity.authenticator

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import android.content.res.Configuration
import androidx.core.graphics.ColorUtils
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ThemeManagerTest {
    @Test
    fun defaultsFollowPhoneAndModeForcesHalf() {
        val context = withNight(false)
        val night = withNight(true)
        val prefs = context.getSharedPreferences("appearance", Context.MODE_PRIVATE)
        prefs.edit().clear().commit()
        try {
            assertEquals("Busnes", ThemeManager.pairName(context))
            assertEquals(ThemeMode.SYSTEM, ThemeManager.mode(context))
            assertEquals(0xfff8f6f0.toInt(), ThemeManager.color(context, R.color.ky_background))
            assertEquals(0xff182326.toInt(), ThemeManager.color(night, R.color.ky_background))
            ThemeManager.setPair(context, "Ky")
            assertEquals(0xffeef2f6.toInt(), ThemeManager.color(context, R.color.ky_background))
            assertEquals(0xff10161e.toInt(), ThemeManager.color(night, R.color.ky_background))
            ThemeManager.setMode(context, ThemeMode.DARK)
            assertEquals(0xff10161e.toInt(), ThemeManager.color(context, R.color.ky_background))
            ThemeManager.setMode(context, ThemeMode.LIGHT)
            assertEquals(0xffeef2f6.toInt(), ThemeManager.color(night, R.color.ky_background))
            ThemeManager.setPair(context, "unknown")
            assertEquals("Ky", ThemeManager.pairName(context))
        } finally {
            prefs.edit().clear().commit()
        }
    }

    @Test
    fun legacySavedThemeMigratesOnceAndIsRemoved() {
        val context = withNight(false)
        val prefs = context.getSharedPreferences("appearance", Context.MODE_PRIVATE)
        try {
            prefs.edit().clear().putString("theme", "Busnes Dark").commit()
            assertEquals(0xff182326.toInt(), ThemeManager.color(context, R.color.ky_background))
            assertEquals("Busnes", ThemeManager.pairName(context))
            assertEquals(ThemeMode.DARK, ThemeManager.mode(context))
            assertFalse(prefs.contains("theme"))

            prefs.edit().clear().putString("theme", "Coffee").commit()
            assertEquals("Busnes", ThemeManager.pairName(context))
            assertEquals(ThemeMode.SYSTEM, ThemeManager.mode(context))
            assertFalse(prefs.contains("theme"))
        } finally {
            prefs.edit().clear().commit()
        }
    }

    @Test
    fun everyHalfHasReadableTextOnDevice() {
        val prefs = withNight(false).getSharedPreferences("appearance", Context.MODE_PRIVATE)
        try {
            for (name in ThemeManager.pairNames()) for (night in listOf(false, true)) {
                val context = withNight(night)
                ThemeManager.setPair(context, name)
                ThemeManager.setMode(context, ThemeMode.SYSTEM)
                for (surface in listOf(R.color.ky_background, R.color.ky_surface)) {
                    for (text in listOf(R.color.ky_text, R.color.ky_heading, R.color.ky_danger, R.color.ky_warning, R.color.ky_success)) {
                        assertTrue("$name night=$night", ColorUtils.calculateContrast(
                            ThemeManager.color(context, text), ThemeManager.color(context, surface),
                        ) >= 4.5)
                    }
                }
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
