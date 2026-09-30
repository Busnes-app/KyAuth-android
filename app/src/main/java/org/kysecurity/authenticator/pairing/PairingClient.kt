package org.kysecurity.authenticator.pairing

import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection

private val LEVELS = setOf("none", "tee", "strongbox")

class PairingClient {
    fun register(
        pairing: QrPairing,
        deviceName: String,
        deviceIdentifier: String,
        pushToken: String? = null,
        publicKeyBase64: String = DeviceSigningKey.publicKeyBase64(),
        attestationChain: List<String> = emptyList(),
    ): PairedAccount {
        require(deviceName.isNotBlank()) { "Device name is required" }
        require(deviceIdentifier.isNotBlank()) { "Device identifier is required" }
        require(publicKeyBase64.isNotBlank()) { "Device public key is required" }

        val endpoint = PairingEndpoint.validatedRegistrationUrl(pairing.serverUrl, pairing.registrationUrl)
        val request = registrationRequestJson(pairing, deviceName, deviceIdentifier, pushToken, publicKeyBase64, attestationChain)

        val connection = (endpoint.toURL().openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 10_000
            readTimeout = 10_000
            doOutput = true
            instanceFollowRedirects = false
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Accept", "application/json")
        }

        try {
            connection.outputStream.bufferedWriter(Charsets.UTF_8).use { it.write(request) }
            val body = (if (connection.responseCode in 200..299) connection.inputStream else connection.errorStream)
                ?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
            val response = JSONObject(body.ifBlank { "{}" })
            if (connection.responseCode !in 200..299 || !response.optBoolean("success")) {
                val errorMsg = response.optString(
                    "error_description",
                    response.optString("error", "Pairing failed (${connection.responseCode})"),
                )
                throw IllegalStateException(errorMsg)
            }
            return parseRegistration(body, pairing, deviceName)
        } finally {
            connection.disconnect()
        }
    }

    internal fun parseRegistration(body: String, pairing: QrPairing, deviceName: String): PairedAccount {
        val response = JSONObject(body.ifBlank { "{}" })
        val deviceId = response.optString("deviceId")
        require(deviceId.isNotBlank()) { "KyIdentity did not return a device ID" }
        val respDevice = response.optJSONObject("device")
        val userId = respDevice?.optString("userId")?.takeIf { it.isNotBlank() } ?: pairing.userId
        val level = respDevice?.optString("attestedLevel")?.takeIf { it in LEVELS } ?: "none"
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
        )
    }

    internal fun registrationRequestJson(
        pairing: QrPairing,
        deviceName: String,
        deviceIdentifier: String,
        pushToken: String?,
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
        if (!pushToken.isNullOrBlank()) {
            put("pushToken", pushToken.trim())
        }
        if (attestationChain.isNotEmpty()) put("attestation", JSONArray(attestationChain))
    }.toString()
}
