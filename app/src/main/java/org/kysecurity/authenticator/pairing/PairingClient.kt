package org.kysecurity.authenticator.pairing

import org.json.JSONArray
import org.json.JSONObject
import org.kysecurity.authenticator.mfa.MfaMessage

private val LEVELS = setOf("none", "tee", "strongbox")
internal const val REPLY_UNVERIFIED = "The server's pairing reply could not be verified."
internal const val NEEDS_USER_ID = "Pairing with a token needs the user ID. Scan the QR code, or enter the user ID."

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
            .toByteArray(Charsets.UTF_8)
        val reply = ServerHttp.send(endpoint, "POST", "application/json", request, proofHeaders(pairing, request))
        return accept(pairing, request, reply, deviceName, attestationChain)
    }

    /** The proof header for a QR/token pairing over the exact [request] bytes; none for PIN pairing. */
    internal fun proofHeaders(pairing: QrPairing, request: ByteArray): Map<String, String> {
        val token = pairing.pairingToken?.takeIf { it.isNotBlank() } ?: return emptyMap()
        require(!pairing.userId.isNullOrBlank()) { NEEDS_USER_ID }
        return mapOf(PairingProof.HEADER to PairingProof.requestProof(PairingProof.key(token), MfaMessage.origin(pairing.serverUrl), request))
    }

    /** Verifies a token pairing's reply over its exact bytes before anything is parsed. */
    internal fun accept(
        pairing: QrPairing,
        request: ByteArray,
        reply: ServerHttp.Response,
        deviceName: String,
        attestationChain: List<String> = emptyList(),
    ): PairedAccount {
        if (!reply.ok) throw IllegalStateException(reply.error("Pairing failed"))
        val token = pairing.pairingToken?.takeIf { it.isNotBlank() }
        if (token != null && !PairingProof.replyVerified(
                PairingProof.key(token), MfaMessage.origin(pairing.serverUrl), request, reply.bytes,
                reply.singleHeader(PairingProof.HEADER),
            )
        ) {
            throw IllegalStateException(REPLY_UNVERIFIED)
        }
        val body = reply.body
        if (!JSONObject(body.ifBlank { "{}" }).optBoolean("success")) throw IllegalStateException(reply.error("Pairing failed"))
        return parseRegistration(body, pairing, deviceName, attestationChain)
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
        // A token pairing proves the token in a header instead (PairingProof); only PIN pairing sends its secret.
        if (pairing.pairingToken.isNullOrBlank() && !pairing.pinCode.isNullOrBlank()) {
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
