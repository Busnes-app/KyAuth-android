package org.kysecurity.authenticator.signon

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TrustedConsumersTest {
    private val play = TrustedConsumers.PINS.getValue("org.kysecurity.mail").first()

    @Test
    fun decide_acceptsPinnedPackageWithPinnedCert() {
        val caller = TrustedConsumers.decide(listOf("org.kysecurity.mail"), { setOf(play) }, null)
        assertEquals("org.kysecurity.mail", caller?.packageName)
        assertEquals("KyPost", caller?.label)
    }

    @Test
    fun decide_refusesUnknownCert() {
        assertNull(TrustedConsumers.decide(listOf("org.kysecurity.mail"), { setOf("00".repeat(32)) }, null))
    }

    @Test
    fun decide_refusesUnknownPackage() {
        assertNull(TrustedConsumers.decide(listOf("com.evil.app"), { setOf(play) }, null))
    }

    @Test
    fun decide_requiresEveryPackageOfUid() {
        assertNull(TrustedConsumers.decide(listOf("org.kysecurity.mail", "com.evil.shared"), { setOf(play) }, null))
    }

    @Test
    fun decide_debugDigestOnlyWhenSupplied() {
        val debug = "ab".repeat(32)
        assertNull(TrustedConsumers.decide(listOf("org.kysecurity.mail"), { setOf(debug) }, null))
        assertEquals("org.kysecurity.mail", TrustedConsumers.decide(listOf("org.kysecurity.mail"), { setOf(debug) }, debug)?.packageName)
    }

    @Test
    fun decide_refusesMixedPinnedAndUnpinnedCerts() {
        assertNull(TrustedConsumers.decide(listOf("org.kysecurity.mail"), { setOf(play, "00".repeat(32)) }, null))
    }

    @Test
    fun manifest_queriesEveryPinnedPackage() {
        var dir: java.io.File? = java.io.File("").absoluteFile
        while (dir != null && !java.io.File(dir, "app/src/main/AndroidManifest.xml").exists() && !java.io.File(dir, "src/main/AndroidManifest.xml").exists()) dir = dir.parentFile
        checkNotNull(dir) { "manifest not found" }
        val file = java.io.File(dir, "app/src/main/AndroidManifest.xml").takeIf { it.exists() } ?: java.io.File(dir, "src/main/AndroidManifest.xml")
        val text = file.readText()
        val queries = Regex("<queries>(.*?)</queries>", RegexOption.DOT_MATCHES_ALL).find(text)?.groupValues?.get(1)
        assertNotNull("no <queries> element", queries)
        val declared = Regex("<package\\s+android:name=\"([^\"]+)\"").findAll(queries!!).map { it.groupValues[1] }.toSet()
        assertTrue("missing from <queries>: ${TrustedConsumers.PINS.keys - declared}", declared.containsAll(TrustedConsumers.PINS.keys))
    }

    @Test
    fun decide_refusesEmptyCertSet() {
        assertNull(TrustedConsumers.decide(listOf("org.kysecurity.mail"), { emptySet() }, play))
    }

    @Test
    fun pins_areRealDigests() {
        val digests = TrustedConsumers.PINS.values.flatten()
        assertTrue(digests.isNotEmpty())
        assertFalse(digests.any { it.startsWith("REPLACE") })
        assertTrue(digests.all { Regex("[0-9a-f]{64}").matches(it) })
    }
}
