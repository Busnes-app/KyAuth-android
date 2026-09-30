package org.kysecurity.authenticator.pairing

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

class PairingClientTest {
    @Test
    fun registrationRequestJson_includesAndroidPushRegistrationFormat() {
        val request = JSONObject(
            PairingClient().registrationRequestJson(
                pairing = QrPairing(
                    serverUrl = "https://signin.example.com",
                    pairingToken = "pair-token",
                ),
                deviceName = " SM-F971U1 ",
                deviceIdentifier = " install-id ",
                pushToken = " fcm-token ",
                publicKeyBase64 = "public-key",
            ),
        )

        assertEquals("pair-token", request.getString("pairingToken"))
        assertEquals("SM-F971U1", request.getString("deviceName"))
        assertEquals("install-id", request.getString("deviceIdentifier"))
        assertEquals("android", request.getString("platform"))
        assertEquals("public-key", request.getString("publicKey"))
        assertEquals("fcm-token", request.getString("pushToken"))
    }

    @Test
    fun parseRegistration_readsCanSignOn() {
        val client = PairingClient()
        val pairing = QrPairing(serverUrl = "https://id.example.com/", pairingToken = "t", username = "alice")
        val on = client.parseRegistration(
            """{"success":true,"deviceId":"dev-1","device":{"userId":"u1","canSignOn":true}}""", pairing, "Pixel",
        )
        assertEquals(true, on.canSignOn)
        assertEquals("u1", on.userId)
        val off = client.parseRegistration("""{"success":true,"deviceId":"dev-1","device":{"userId":"u1"}}""", pairing, "Pixel")
        assertEquals(false, off.canSignOn)
    }

    @Test
    fun registrationRequestJson_includesAttestationChainWhenPresent() {
        val with = JSONObject(PairingClient().registrationRequestJson(
            pairing = QrPairing(serverUrl = "https://signin.example.com", pairingToken = "pair-token"),
            deviceName = "Pixel", deviceIdentifier = "i", pushToken = "fcm", publicKeyBase64 = "pk",
            attestationChain = listOf("leafB64", "intB64", "rootB64"),
        ))
        val arr = with.getJSONArray("attestation")
        assertEquals(3, arr.length()); assertEquals("leafB64", arr.getString(0))
        val without = JSONObject(PairingClient().registrationRequestJson(
            pairing = QrPairing(serverUrl = "https://signin.example.com", pairingToken = "pair-token"),
            deviceName = "Pixel", deviceIdentifier = "i", pushToken = "fcm", publicKeyBase64 = "pk",
            attestationChain = emptyList(),
        ))
        assertEquals(false, without.has("attestation"))
    }

    @Test
    fun parseRegistration_readsAttestedLevelAndBootState() {
        val client = PairingClient()
        val pairing = QrPairing(serverUrl = "https://id.example.com/", pairingToken = "t")
        val attested = client.parseRegistration(
            """{"success":true,"deviceId":"d","device":{"userId":"u","canSignOn":true,"attestedLevel":"strongbox","bootState":"locked-verified"}}""", pairing, "Pixel",
        )
        assertEquals("strongbox", attested.attestedLevel); assertEquals("locked-verified", attested.bootState)
        val old = client.parseRegistration("""{"success":true,"deviceId":"d","device":{"userId":"u"}}""", pairing, "Pixel")
        assertEquals("none", old.attestedLevel); assertEquals("unknown", old.bootState)
        val junk = client.parseRegistration("""{"success":true,"deviceId":"d","device":{"userId":"u","attestedLevel":"platinum"}}""", pairing, "Pixel")
        assertEquals("none", junk.attestedLevel)
    }
}
