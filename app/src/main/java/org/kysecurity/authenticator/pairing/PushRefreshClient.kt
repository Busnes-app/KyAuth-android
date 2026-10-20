package org.kysecurity.authenticator.pairing

import org.json.JSONObject
import org.kysecurity.authenticator.mfa.MfaMessage
import java.security.MessageDigest

/** Tells KyIdentity where to push this device now, signed by the device key. */
class PushRefreshClient {
    fun refresh(serverUrl: String, deviceId: String, push: PushCredential, issuedAtMs: Long, signature: String): Result<Unit> = runCatching {
        val endpoint = PairingEndpoint.deviceUrl(serverUrl, deviceId, "push-token")
        val response = ServerHttp.send(endpoint, "PUT", "application/json", requestJson(push, issuedAtMs, signature))
        check(response.ok) { response.error("Reconnecting sign-in requests failed") }
    }

    companion object {
        // Wire contract: must equal what KyIdentity verifies for a push-token refresh.
        private const val PREFIX = "kyidentity-push-token-v2"

        /** The exact bytes the device key signs to move this device's pushes. */
        fun message(serverUrl: String, deviceId: String, issuedAtMs: Long, push: PushCredential): ByteArray {
            val fields = listOf(
                PREFIX, MfaMessage.origin(serverUrl), deviceId, issuedAtMs.toString(), push.transport,
                sha256Hex(push.token), push.p256dh.orEmpty(), push.auth.orEmpty(),
            )
            require(deviceId.isNotEmpty() && fields.none { '|' in it }) { "Invalid push refresh field" }
            return fields.joinToString("|").toByteArray(Charsets.UTF_8)
        }

        // A keyless FCM credential (a pairing made before KyAuth sent keys) omits them, as at registration, rather than sending them empty.
        internal fun requestJson(push: PushCredential, issuedAtMs: Long, signature: String): String = JSONObject()
            .put("pushToken", push.token)
            .put("pushTransport", push.transport)
            .apply { push.p256dh?.let { put("pushP256dh", it) } }
            .apply { push.auth?.let { put("pushAuth", it) } }
            .put("issuedAt", issuedAtMs)
            .put("signature", signature)
            .toString()

        private fun sha256Hex(value: String): String =
            MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
