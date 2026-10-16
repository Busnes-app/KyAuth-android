package org.kysecurity.authenticator.pairing

import org.json.JSONArray
import org.json.JSONObject

private val LEVELS = setOf("none", "tee", "strongbox")

class PairingClient {
    fun register(
        pairing: QrPairing,
        deviceName: String,
        deviceIdentifier: String,
        push: PushCredential? = null,
        publicKeyBase64: String = DeviceSigningKey.publicKeyBase64(),
        attestationChain: List<String> = emptyList(),
    ): PairedAccount {
        require(deviceName.isNotBlank()) { "Device name is required" }
        require(deviceIdentifier.isNotBlank()) { "Device identifier is required" }
        require(publicKeyBase64.isNotBlank()) { "Device public key is required" }

        val endpoint = PairingEndpoint.validatedRegistrationUrl(pairing.serverUrl, pairing.registrationUrl)
        val request = registrationRequestJson(pairing, deviceName, deviceIdentifier, push, publicKeyBase64, attestationChain)

        val reply = ServerHttp.send(endpoint, "POST", "application/json", request)
        val response = JSONObject(reply.body.ifBlank { "{}" })
        if (!reply.ok || !response.optBoolean("success")) {
            val errorMsg = response.optString(
                "error_description",
                response.optString("error", "Pairing failed (${reply.status})"),
            )
            throw IllegalStateException(errorMsg)
        }
        return parseRegistration(reply.body, pairing, deviceName, attestationChain)
    }

    internal fun parseRegistration(
        body: String,
        pairing: QrPairing,
        deviceName: String,
        attestationChain: List<String> = emptyList(),
        leafLevel: (String) -> Int? = AttestationReason::leafSecurityLevel,
    ): PairedAccount {
        val response = JSONObject(body.ifBlank { "{}" })
        val deviceId = response.optString("deviceId")
        require(deviceId.isNotBlank()) { "KyIdentity did not return a device ID" }
        val respDevice = response.optJSONObject("device")
        val userId = respDevice?.optString("userId")?.takeIf { it.isNotBlank() } ?: pairing.userId
        val level = respDevice?.optString("attestedLevel")?.takeIf { it in LEVELS } ?: "none"
        val reported = respDevice?.let { it.has("attestedLevel") && !it.isNull("attestedLevel") } == true
        val boot = respDevice?.optString("bootState")?.takeIf { it.isNotBlank() } ?: "unknown"
        return PairedAccount(
            serverUrl = pairing.serverUrl.trimEnd('/'),
            deviceId = deviceId,
            deviceName = deviceName.trim(),
            username = pairing.username,
            userId = userId,
            canSignOn = respDevice?.optBoolean("canSignOn", false) ?: false,
            attestedLevel = level,
            bootState = boot,
            attestationReason = AttestationReason.classify(level, reported, attestationChain, leafLevel),
        )
    }

    internal fun registrationRequestJson(
        pairing: QrPairing,
        deviceName: String,
        deviceIdentifier: String,
        push: PushCredential?,
        publicKeyBase64: String,
        attestationChain: List<String> = emptyList(),
    ): String = JSONObject().apply {
        if (!pairing.pairingToken.isNullOrBlank()) {
            put("pairingToken", pairing.pairingToken)
        }
        if (!pairing.pinCode.isNullOrBlank()) {
            put("pinCode", pairing.pinCode)
        }
        if (!pairing.userId.isNullOrBlank()) {
            put("userId", pairing.userId)
        }
        put("deviceName", deviceName.trim())
        put("deviceIdentifier", deviceIdentifier.trim())
        put("platform", "android")
        put("publicKey", publicKeyBase64)
        if (push != null) {
            put("pushToken", push.token.trim())
            put("pushTransport", push.transport)
            push.p256dh?.let { put("pushP256dh", it) }
            push.auth?.let { put("pushAuth", it) }
        }
        if (attestationChain.isNotEmpty()) put("attestation", JSONArray(attestationChain))
    }.toString()
}
