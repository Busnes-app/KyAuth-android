package org.kysecurity.authenticator.pairing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class PushKeysTest {
    @Test
    fun generatedKeysHaveTheWireShapeAndSurviveTheirStoredForm() {
        val generated = PushKeys.generate()
        assertEquals(65, PushKeys.unb64(generated.p256dh).size)
        assertEquals(4.toByte(), PushKeys.unb64(generated.p256dh)[0])
        assertEquals(16, PushKeys.unb64(generated.auth).size)
        assertFalse(generated.p256dh.contains('=') || generated.auth.contains('='))
        PushKeys.publicKey(generated.publicPoint) // on the curve

        val restored = PushKeys.decode(generated.encode())!!
        assertEquals(generated.p256dh, restored.p256dh)
        assertEquals(generated.auth, restored.auth)
        assertEquals(generated.privateKey.s, restored.privateKey.s)
    }

    @Test
    fun everyGenerationIsFresh() {
        val a = PushKeys.generate()
        val b = PushKeys.generate()
        assertNotEquals(a.p256dh, b.p256dh)
        assertNotEquals(a.auth, b.auth)
    }

    @Test
    fun decodeRefusesAnythingElse() {
        assertNull(PushKeys.decode(null))
        assertNull(PushKeys.decode(""))
        assertNull(PushKeys.decode("a.b"))
        val good = PushKeys.generate().encode().split('.')
        assertNull(PushKeys.decode(listOf(good[0], good[1], "AAAA").joinToString("."))) // short auth
        assertNull(PushKeys.decode(listOf("AAAA", good[1], good[2]).joinToString("."))) // short scalar
    }

    @Test
    fun refusesPointsOffTheCurve() {
        val point = PushKeys.generate().publicPoint.copyOf()
        point[64] = (point[64].toInt() xor 1).toByte()
        assertThrows(IllegalArgumentException::class.java) { PushKeys.publicKey(point) }
        assertThrows(IllegalArgumentException::class.java) { PushKeys.publicKey(point.copyOf(33)) }
    }

    @Test
    fun toStringRedactsKeys() {
        val keys = PushKeys.generate()
        val text = keys.toString()
        for (secret in listOf(keys.p256dh, keys.auth, keys.encode())) assertFalse(secret in text)
    }
}
