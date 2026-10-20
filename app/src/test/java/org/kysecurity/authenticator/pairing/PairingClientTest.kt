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
                push = PushCredential(PushCredential.FCM, " fcm-token "),
                publicKeyBase64 = "public-key",
            ),
        )

        assertEquals("pair-token", request.getString("pairingToken"))
        assertEquals("SM-F971U1", request.getString("deviceName"))
        assertEquals("install-id", request.getString("deviceIdentifier"))
        assertEquals("android", request.getString("platform"))
        assertEquals("public-key", request.getString("publicKey"))
        assertEquals("fcm-token", request.getString("pushToken"))
        assertEquals("fcm", request.getString("pushTransport"))
        assertEquals(false, request.has("pushP256dh"))
        assertEquals(false, request.has("pushAuth"))
    }

    @Test
    fun registrationRequestJson_carriesFcmKeys() {
        val keys = PushKeys.generate()
        val request = JSONObject(
            PairingClient().registrationRequestJson(
                pairing = QrPairing(serverUrl = "https://signin.example.com", pairingToken = "pair-token"),
                deviceName = "Pixel",
                deviceIdentifier = "i",
                push = PushCredential(PushCredential.FCM, "fcm-token").withKeys(keys),
                publicKeyBase64 = "pk",
            ),
        )
        assertEquals("fcm", request.getString("pushTransport"))
        assertEquals(keys.p256dh, request.getString("pushP256dh"))
        assertEquals(keys.auth, request.getString("pushAuth"))
    }

    @Test
    fun registrationRequestJson_carriesUnifiedPushKeys() {
        val request = JSONObject(
            PairingClient().registrationRequestJson(
                pairing = QrPairing(serverUrl = "https://signin.example.com", pairingToken = "pair-token"),
                deviceName = "Pixel",
                deviceIdentifier = "i",
                push = PushCredential(PushCredential.UNIFIED_PUSH, "https://ntfy.example.net/upAbC123?up=1", "p256", "authsecret"),
                publicKeyBase64 = "pk",
            ),
        )
        assertEquals("https://ntfy.example.net/upAbC123?up=1", request.getString("pushToken"))
        assertEquals("unifiedpush", request.getString("pushTransport"))
        assertEquals("p256", request.getString("pushP256dh"))
        assertEquals("authsecret", request.getString("pushAuth"))
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
            deviceName = "Pixel", deviceIdentifier = "i", push = PushCredential(PushCredential.FCM, "fcm"), publicKeyBase64 = "pk",
            attestationChain = listOf("leafB64", "intB64", "rootB64"),
        ))
        val arr = with.getJSONArray("attestation")
        assertEquals(3, arr.length()); assertEquals("leafB64", arr.getString(0))
        val without = JSONObject(PairingClient().registrationRequestJson(
            pairing = QrPairing(serverUrl = "https://signin.example.com", pairingToken = "pair-token"),
            deviceName = "Pixel", deviceIdentifier = "i", push = PushCredential(PushCredential.FCM, "fcm"), publicKeyBase64 = "pk",
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

    @Test
    fun parseRegistration_classifiesAttestationReason() {
        val client = PairingClient()
        val pairing = QrPairing(serverUrl = "https://id.example.com/", pairingToken = "t")
        fun reason(device: String, chain: List<String> = emptyList(), leaf: Int? = null) = client.parseRegistration(
            """{"success":true,"deviceId":"d","device":{"userId":"u"$device}}""", pairing, "Pixel", chain, { leaf },
        ).attestationReason
        assertEquals("server-unsupported", reason(""))
        assertEquals("server-unsupported", reason(""","attestedLevel":null"""))
        assertEquals("keystore-software", reason(""","attestedLevel":"none""""))
        assertEquals("keystore-software", reason(""","attestedLevel":"platinum""""))
        assertEquals("keystore-software", reason(""","attestedLevel":"none"""", listOf("leaf"), 0))
        assertEquals("not-accepted", reason(""","attestedLevel":"none"""", listOf("leaf"), 1))
        assertEquals("", reason(""","attestedLevel":"tee""""))
    }
}
