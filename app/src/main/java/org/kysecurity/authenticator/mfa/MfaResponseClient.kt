package org.kysecurity.authenticator.mfa

import org.json.JSONObject
import org.kysecurity.authenticator.pairing.PairingEndpoint
import org.kysecurity.authenticator.pairing.ServerHttp
import java.net.URI

sealed class MfaResponseResult {
    data class Success(val approved: Boolean, val deviceId: String) : MfaResponseResult()
    data class Error(val message: String) : MfaResponseResult()
}

class MfaResponseClient {
    fun respond(
        serverUrl: String,
        challengeId: String,
        deviceId: String,
        selectedDigits: String,
        approve: Boolean,
        signature: String,
    ): MfaResponseResult = try {
        require(challengeId.isNotBlank()) { "Challenge ID is required" }
        require(signature.isNotBlank()) { "Device signature is required" }

        val server = PairingEndpoint.registrationUrl(serverUrl)
        val basePath = server.path.removeSuffix("/api/notifications/native/register")
        val respondUrl = "${server.scheme}://${server.host}${if (server.port != -1) ":${server.port}" else ""}$basePath/api/mfa/push/respond"

        val request = JSONObject()
            .put("challengeId", challengeId.trim())
            .put("deviceId", deviceId)
            .put("selectedDigits", selectedDigits.trim())
            .put("approve", approve)
            .put("signature", signature.trim())
            .toString()

        val response = ServerHttp.send(URI(respondUrl), "POST", "application/json", request)
        parseResponse(response.status, JSONObject(response.body.ifBlank { "{}" }), challengeId.trim())
    } catch (e: Exception) {
        MfaResponseResult.Error(e.message ?: "Network error during MFA response")
    }

    /**
     * A 2xx with no decision in it is a protocol error, not an approval. Reporting back whatever
     * the client asked for would turn a broken or hostile server into a silent "approved".
     */
    internal fun parseResponse(
        responseCode: Int,
        response: JSONObject,
        challengeId: String,
    ): MfaResponseResult {
        if (responseCode !in 200..299) {
            val errorMsg = response.optString(
                "error_description",
                response.optString("error", "Push response failed ($responseCode)"),
            )
            return MfaResponseResult.Error(errorMsg)
        }

        val echoedId = response.optString("challengeId").takeIf { it.isNotBlank() }
        if (echoedId != null && echoedId != challengeId) {
            return MfaResponseResult.Error("Server answered a different challenge")
        }

        val approved = when {
            response.has("approved") -> response.optBoolean("approved")
            response.has("success") -> response.optBoolean("success")
            else -> return MfaResponseResult.Error("Server did not report a decision")
        }
        return MfaResponseResult.Success(approved = approved, deviceId = response.optString("deviceId"))
    }
}
