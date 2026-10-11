package org.kysecurity.authenticator.pairing

import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class PushCredentialTest {
    @Test
    fun toStringRedactsTokenAndKeys() {
        val text = PushCredential(PushCredential.UNIFIED_PUSH, "https://ntfy.example.net/secret-topic", "p256-key", "auth-key").toString()
        for (secret in listOf("secret-topic", "p256-key", "auth-key")) assertFalse(text, secret in text)
    }

    @Test
    fun unifiedPushRequiresKeysAndFcmRefusesThem() {
        assertThrows(IllegalArgumentException::class.java) { PushCredential(PushCredential.UNIFIED_PUSH, "https://e", "p", null) }
        assertThrows(IllegalArgumentException::class.java) { PushCredential(PushCredential.FCM, "t", "p", "a") }
        assertThrows(IllegalArgumentException::class.java) { PushCredential("apns", "t") }
    }
}
