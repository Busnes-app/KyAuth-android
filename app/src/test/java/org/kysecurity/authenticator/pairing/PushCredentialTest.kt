package org.kysecurity.authenticator.pairing

import org.junit.Assert.assertEquals
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
    fun unifiedPushRequiresKeysAndFcmTakesBothOrNeither() {
        assertThrows(IllegalArgumentException::class.java) { PushCredential(PushCredential.UNIFIED_PUSH, "https://e", "p", null) }
        assertThrows(IllegalArgumentException::class.java) { PushCredential(PushCredential.UNIFIED_PUSH, "https://e") }
        assertThrows(IllegalArgumentException::class.java) { PushCredential(PushCredential.FCM, "t", "p", null) }
        assertThrows(IllegalArgumentException::class.java) { PushCredential(PushCredential.FCM, "t", null, "a") }
        assertThrows(IllegalArgumentException::class.java) { PushCredential(PushCredential.FCM, "t", "", "") }
        assertThrows(IllegalArgumentException::class.java) { PushCredential("apns", "t") }
        PushCredential(PushCredential.FCM, "t", "p", "a")
        PushCredential(PushCredential.FCM, "t")
    }

    @Test
    fun withKeysSealsAndUnsealsAnFcmCredential() {
        val keys = PushKeys.generate()
        val sealed = PushCredential(PushCredential.FCM, "t").withKeys(keys)
        assertEquals(keys.p256dh, sealed.p256dh)
        assertEquals(keys.auth, sealed.auth)
        assertEquals(PushCredential(PushCredential.FCM, "t"), sealed.withKeys(null))
    }
}
