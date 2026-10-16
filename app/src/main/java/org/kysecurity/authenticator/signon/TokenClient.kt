package org.kysecurity.authenticator.signon

import org.json.JSONObject
import org.kysecurity.authenticator.pairing.PairingEndpoint
import org.kysecurity.authenticator.pairing.ServerHttp
import java.net.URLEncoder

sealed class TokenResult {
    data class Success(val idToken: String) : TokenResult() {
        override fun toString() = "Success(redacted)"
    }
    data class Failure(val userMessage: String) : TokenResult()
}

/** Redeems a device assertion at KyIdentity's token endpoint. The ID token is returned, never stored. Blocking: call off the main thread. */
class TokenClient {
    fun redeem(serverUrl: String, clientId: String, assertion: String): TokenResult {
        val endpoint = try {
            PairingEndpoint.tokenUrl(serverUrl)
        } catch (e: IllegalArgumentException) {
            return TokenResult.Failure("The paired server address is not valid.")
        } catch (e: java.net.URISyntaxException) {
            return TokenResult.Failure("The paired server address is not valid.")
        }
        return try {
            val response = ServerHttp.send(endpoint, "POST", "application/x-www-form-urlencoded", formBody(clientId, assertion))
            parse(response.status, response.body)
        } catch (e: Exception) {
            TokenResult.Failure("Could not reach KyIdentity. Check the connection and try again.")
        }
    }

    internal fun formBody(clientId: String, assertion: String): String = listOf(
        "grant_type" to "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion" to assertion,
        "client_id" to clientId,
    ).joinToString("&") { (k, v) -> k + "=" + URLEncoder.encode(v, "UTF-8") }

    internal fun parse(status: Int, body: String): TokenResult {
        val json = runCatching { JSONObject(body.ifBlank { "{}" }) }.getOrElse { JSONObject() }
        if (status == 429) return TokenResult.Failure("KyIdentity is busy. Try again in a minute.")
        if (status !in 200..299) {
            if (json.optString("error_description") == "device_signon_disabled") {
                return TokenResult.Failure(
                    "Sign-in from this phone is turned off. Turn it on for this device on the KyIdentity devices page, then try again.",
                )
            }
            if (json.optString("error_description") == "signon_not_permitted") {
                return TokenResult.Failure("This account cannot sign in to apps from this phone right now. Use web sign-in.")
            }
            return TokenResult.Failure("KyIdentity refused the sign-in ($status).")
        }
        val idToken = json.optString("id_token")
        if (idToken.isBlank()) return TokenResult.Failure("KyIdentity returned no identity token.")
        return TokenResult.Success(idToken)
    }
}
