package org.kysecurity.authenticator.pairing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.kysecurity.authenticator.pairing.DeviceRevokeClient.Outcome

class DeviceRevokeClientTest {
    // Golden vector shared with KyIdentity-server (internal/mfa/push_target_test.go).
    @Test
    fun messageMatchesGoldenVector() {
        assertEquals(
            "kyidentity-device-revoke-v1|https://id.example.com|d-456|1791331200000",
            String(DeviceRevokeClient.message("https://id.example.com", "d-456", 1791331200000), Charsets.UTF_8),
        )
    }

    @Test
    fun refusesSeparatorOrEmptyDevice() {
        assertThrows(IllegalArgumentException::class.java) { DeviceRevokeClient.message("https://id.example.com", "d|1", 1) }
        assertThrows(IllegalArgumentException::class.java) { DeviceRevokeClient.message("https://id.example.com", "", 1) }
    }

    @Test
    fun onlyTheRequiredFactorRefusalKeepsThePairing() {
        assertEquals(Outcome.REVOKED, DeviceRevokeClient.outcome(204, ""))
        assertEquals(Outcome.REQUIRED_FACTOR, DeviceRevokeClient.outcome(409, """{"error":"required_factor"}"""))
        assertEquals(Outcome.FAILED, DeviceRevokeClient.outcome(409, """{"error":"replayed_request"}"""))
        assertEquals(Outcome.FAILED, DeviceRevokeClient.outcome(401, """{"error":"device_authentication_failed"}"""))
        assertEquals(Outcome.FAILED, DeviceRevokeClient.outcome(404, "not json"))
    }

    @Test
    fun revokeUrlSitsBesideThePushTokenRoute() {
        assertEquals(
            "https://id.example.com/base/api/notifications/native/devices/d%2F1/revoke",
            PairingEndpoint.deviceUrl("https://id.example.com/base", "d/1", "revoke").toString(),
        )
    }
}
