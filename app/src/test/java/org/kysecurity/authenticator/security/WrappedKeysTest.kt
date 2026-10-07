package org.kysecurity.authenticator.security

import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Test

class WrappedKeysTest {
    private val totp = ByteArray(32) { it.toByte() }
    private fun b64(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)

    @Test
    fun roundTrips() {
        assertArrayEquals(totp, parseWrappedKeys(serializeWrappedKeys(totp)))
    }

    @Test
    fun ignoresThePasswordsKeyOlderDevBuildsWrote() {
        val old = """{"totp":"${b64(totp)}","passwords":"${b64(ByteArray(32) { 7 })}"}"""
        assertArrayEquals(totp, parseWrappedKeys(old.toByteArray()))
    }
}
