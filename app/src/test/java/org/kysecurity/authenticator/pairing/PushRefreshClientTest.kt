package org.kysecurity.authenticator.pairing

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class PushRefreshClientTest {
    private val p256dh = "BLO9a5hWe8nCmwQX1aEnHLLnt8zkEd8orUdvm7-T9G4iMCY1nFt6ZzoFQA9EFaeHLGtbLcxSsDi0zCgJqaMqF6k"
    private val auth = "MDEyMzQ1Njc4OWFiY2RlZg"
    private val unifiedPush = PushCredential(PushCredential.UNIFIED_PUSH, "https://ntfy.example.net/upAbC123?up=1", p256dh, auth)

    private fun message(push: PushCredential) =
        String(PushRefreshClient.message("https://id.example.com", "d-456", 1791331200000, push), Charsets.UTF_8)

    // Golden vectors shared with KyIdentity-server.
    @Test
    fun unifiedPushMessageMatchesGoldenVector() {
        assertEquals(
            "kyidentity-push-token-v2|https://id.example.com|d-456|1791331200000|unifiedpush|" +
                "8148d101f0613cac03f05c9530160b99c97e54841c0858e6a07b6deb9ab7ee2f|$p256dh|$auth",
            message(unifiedPush),
        )
    }

    @Test
    fun fcmMessageMatchesGoldenVector() {
        assertEquals(
            "kyidentity-push-token-v2|https://id.example.com|d-456|1791331200000|fcm|" +
                "3cfaa3f1d62d114805029366153fbb440a2d4e4b56406a04830579ac65db6a5c||",
            message(PushCredential(PushCredential.FCM, "fcm-token-1")),
        )
    }

    @Test
    fun refusesSeparatorInSignedField() {
        assertThrows(IllegalArgumentException::class.java) {
            PushRefreshClient.message("https://id.example.com", "d|456", 1L, unifiedPush)
        }
        assertThrows(IllegalArgumentException::class.java) {
            PushRefreshClient.message("https://id.example.com", "d-456", 1L, unifiedPush.copy(auth = "a|b"))
        }
    }

    @Test
    fun requestCarriesKeysOnlyForUnifiedPush() {
        val up = JSONObject(PushRefreshClient.requestJson(unifiedPush, 1791331200000, "sig"))
        assertEquals("https://ntfy.example.net/upAbC123?up=1", up.getString("pushToken"))
        assertEquals("unifiedpush", up.getString("pushTransport"))
        assertEquals(p256dh, up.getString("pushP256dh"))
        assertEquals(auth, up.getString("pushAuth"))
        assertEquals(1791331200000, up.getLong("issuedAt"))
        assertEquals("sig", up.getString("signature"))
        val fcm = JSONObject(PushRefreshClient.requestJson(PushCredential(PushCredential.FCM, "t"), 1L, "sig"))
        assertEquals("fcm", fcm.getString("pushTransport"))
        assertFalse(fcm.has("pushP256dh"))
        assertFalse(fcm.has("pushAuth"))
    }
}
