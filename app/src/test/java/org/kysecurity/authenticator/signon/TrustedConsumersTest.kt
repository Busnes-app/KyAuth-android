package org.kysecurity.authenticator.signon

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
    fun isTrusted_requiresEveryPackageOfUid() {
        assertNull(TrustedConsumers.decide(listOf("org.kysecurity.mail", "com.evil.shared"), { setOf(play) }, null))
    }

    @Test
    fun decide_debugDigestOnlyWhenSupplied() {
        val debug = "ab".repeat(32)
        assertNull(TrustedConsumers.decide(listOf("org.kysecurity.mail"), { setOf(debug) }, null))
        assertEquals("org.kysecurity.mail", TrustedConsumers.decide(listOf("org.kysecurity.mail"), { setOf(debug) }, debug)?.packageName)
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
