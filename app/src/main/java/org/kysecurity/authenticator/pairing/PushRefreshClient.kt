package org.kysecurity.authenticator.pairing

import org.json.JSONObject
import org.kysecurity.authenticator.mfa.MfaMessage
import java.net.HttpURLConnection
import java.net.URI
import java.net.URLEncoder
import java.security.MessageDigest

/** Tells KyIdentity where to push this device now, signed by the device key. */
class PushRefreshClient {
    fun refresh(serverUrl: String, deviceId: String, push: PushCredential, issuedAtMs: Long, signature: String): Result<Unit> = runCatching {
        val register = PairingEndpoint.registrationUrl(serverUrl)
        val base = register.path.removeSuffix("/api/notifications/native/register")
        val path = "$base/api/notifications/native/devices/${URLEncoder.encode(deviceId, "UTF-8").replace("+", "%20")}/push-token"
        val endpoint = URI("${register.scheme}://${register.rawAuthority}$path")

        val connection = (endpoint.toURL().openConnection() as HttpURLConnection).apply {
            requestMethod = "PUT"
            connectTimeout = 10_000
            readTimeout = 10_000
            doOutput = true
            instanceFollowRedirects = false
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Accept", "application/json")
        }
        try {
            connection.outputStream.bufferedWriter(Charsets.UTF_8).use { it.write(requestJson(push, issuedAtMs, signature)) }
            val code = connection.responseCode
            if (code !in 200..299) {
                val body = connection.errorStream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
                val error = runCatching { JSONObject(body) }.getOrNull()
                throw IllegalStateException(
                    error?.optString("error_description")?.takeIf { it.isNotBlank() }
                        ?: error?.optString("error")?.takeIf { it.isNotBlank() }
                        ?: "Reconnecting sign-in requests failed ($code)",
                )
            }
        } finally {
            connection.disconnect()
        }
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

        // FCM carries no keys, so they are omitted (as at registration) rather than sent empty.
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
