package org.kysecurity.authenticator.mfa

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import org.kysecurity.authenticator.pairing.PairedAccount

object MfaPushChallengeParser {
    const val MAX_EXPIRES_AFTER_MS = 10 * 60 * 1000L
    const val MAX_DECOYS = 3

    private val DIGITS = Regex("\\d{2}")

    private val PURPOSES = setOf("login", "step_up")

    /**
     * Parses an FCM data message into a challenge.
     *
     * [paired] is the only server a response may be sent to, and the push must name this device and
     * its account: a push for another device or user, or one naming its own server, is refused.
     * Missing or unknown purpose, and an expiry that is absent, past or more than
     * [MAX_EXPIRES_AFTER_MS] ahead, are refused rather than defaulted or clamped.
     */
    fun parse(data: Map<String, String>, paired: PairedAccount?, nowMs: Long = System.currentTimeMillis()): MfaChallenge {
        require(paired != null && paired.serverUrl.isNotBlank() && paired.deviceId.isNotBlank()) { "KyAuth is not paired with a server" }
        val userId = paired.userId
        require(!userId.isNullOrBlank()) { "This pairing has no account; pair KyAuth again" }
        require(firstOrNull(data, "deviceId") == paired.deviceId) { "Push is for another device" }
        require(firstOrNull(data, "deviceUserId") == userId) { "Push is for another account" }
        val serverUrl = paired.serverUrl.trim()

        val challengeId = first(data, "challengeId", "challenge_id", "id")
        val matchDigits = firstOrNull(data, "matchDigits", "match_digits", "match").orEmpty()
        require(matchDigits.isBlank() || DIGITS.matches(matchDigits)) { "Malformed match digits" }

        val decoys = parseDecoys(firstOrNull(data, "decoyDigits", "decoy_digits", "decoys"))
            .filter { DIGITS.matches(it) }
            .distinct()
            .filter { it != matchDigits }
            .take(MAX_DECOYS)

        val purpose = firstOrNull(data, "purpose")
        require(purpose != null && purpose in PURPOSES) { "Unknown push purpose" }
        val expiresAt = firstOrNull(data, "expiresAtEpochMs")?.toLongOrNull()
        require(expiresAt != null && expiresAt > nowMs) { "Challenge has expired or has no expiry" }
        require(expiresAt <= nowMs + MAX_EXPIRES_AFTER_MS) { "Challenge expiry is too far ahead" }

        return MfaChallenge(
            challengeId = challengeId,
            matchDigits = matchDigits,
            decoyDigits = decoys,
            serverUrl = serverUrl,
            username = firstOrNull(data, "username", "user"),
            purpose = purpose,
            expiresAtEpochMs = expiresAt,
        )
    }

    private fun first(data: Map<String, String>, vararg keys: String): String =
        firstOrNull(data, *keys) ?: error("MFA push payload missing ${keys.first()}")

    private fun firstOrNull(data: Map<String, String>, vararg keys: String): String? =
        keys.firstNotNullOfOrNull { key -> data[key]?.trim()?.takeIf { it.isNotBlank() } }

    private fun parseDecoys(raw: String?): List<String> {
        if (raw.isNullOrBlank()) return emptyList()
        return if (raw.trim().startsWith("[")) {
            val array = JSONArray(raw)
            (0 until array.length()).mapNotNull { array.optString(it).trim().takeIf { value -> value.isNotBlank() } }
        } else {
            raw.split(',', '|', ' ').mapNotNull { it.trim().takeIf { value -> value.isNotBlank() } }
        }
    }
}

class MfaPushChallengeStore(context: Context) {
    private val preferences = context.getSharedPreferences("mfa_push_challenge", Context.MODE_PRIVATE)

    fun save(challenge: MfaChallenge) {
        preferences.edit().putString("challenge", encode(challenge)).apply()
    }

    fun load(): MfaChallenge? {
        val value = preferences.getString("challenge", null) ?: return null
        val challenge = runCatching { decode(value) }.getOrNull() ?: return null
        if (isExpired(challenge)) {
            clear()
            return null
        }
        return challenge
    }

    fun isExpired(challenge: MfaChallenge, nowMs: Long = System.currentTimeMillis()): Boolean =
        nowMs >= challenge.expiresAtEpochMs

    fun secondsRemaining(challenge: MfaChallenge, nowMs: Long = System.currentTimeMillis()): Long =
        maxOf(0, (challenge.expiresAtEpochMs - nowMs + 999) / 1_000)

    fun clear() {
        preferences.edit().clear().apply()
    }

    private fun encode(challenge: MfaChallenge): String = JSONObject()
        .put("challengeId", challenge.challengeId)
        .put("matchDigits", challenge.matchDigits)
        .put("decoyDigits", JSONArray(challenge.decoyDigits))
        .put("serverUrl", challenge.serverUrl)
        .put("username", challenge.username)
        .put("purpose", challenge.purpose)
        .put("expiresAtEpochMs", challenge.expiresAtEpochMs)
        .toString()

    private fun decode(value: String): MfaChallenge {
        val json = JSONObject(value)
        val decoys = json.optJSONArray("decoyDigits")
        return MfaChallenge(
            challengeId = json.getString("challengeId"),
            matchDigits = json.optString("matchDigits"),
            decoyDigits = if (decoys == null) emptyList() else (0 until decoys.length()).map { decoys.getString(it) },
            serverUrl = json.getString("serverUrl"),
            username = json.optString("username").takeIf { it.isNotBlank() },
            purpose = json.getString("purpose"),
            expiresAtEpochMs = json.getLong("expiresAtEpochMs"),
        )
    }
}
