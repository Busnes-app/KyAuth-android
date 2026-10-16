package org.kysecurity.authenticator.pairing

import org.json.JSONObject
import org.kysecurity.authenticator.mfa.MfaMessage

/** Asks KyIdentity to delete this device's record, signed by the device key. */
object DeviceRevokeClient {
    // Wire contract: must equal what KyIdentity verifies for a device revoke.
    private const val PREFIX = "kyidentity-device-revoke-v1"

    enum class Outcome {
        REVOKED,

        /** This phone is the account's last factor its enrollment policy requires; KyIdentity kept it. */
        REQUIRED_FACTOR,

        /** Unreachable, refused, or a server too old for the route. */
        FAILED,
    }

    /** The exact bytes the device key signs to delete this device. */
    fun message(serverUrl: String, deviceId: String, issuedAtMs: Long): ByteArray {
        val fields = listOf(PREFIX, MfaMessage.origin(serverUrl), deviceId, issuedAtMs.toString())
        require(deviceId.isNotEmpty() && fields.none { '|' in it }) { "Invalid device revoke field" }
        return fields.joinToString("|").toByteArray(Charsets.UTF_8)
    }

    /** Blocking: call off the main thread. */
    fun revoke(serverUrl: String, deviceId: String, issuedAtMs: Long, signature: String): Outcome = runCatching {
        val body = JSONObject().put("issuedAt", issuedAtMs).put("signature", signature).toString()
        val response = ServerHttp.send(PairingEndpoint.deviceUrl(serverUrl, deviceId, "revoke"), "POST", "application/json", body)
        outcome(response.status, response.body)
    }.getOrDefault(Outcome.FAILED)

    internal fun outcome(status: Int, body: String): Outcome = when {
        status in 200..299 -> Outcome.REVOKED
        status == 409 && runCatching { JSONObject(body).optString("error") }.getOrNull() == "required_factor" -> Outcome.REQUIRED_FACTOR
        else -> Outcome.FAILED
    }
}
