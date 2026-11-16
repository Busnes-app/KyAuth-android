package org.kysecurity.authenticator.pairing

import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * KyAuth pairing proof v1 (wire contract with KyIdentity). The QR token never crosses the wire:
 * both sides MAC the exact bytes they send under K = HMAC-SHA256(token, "kyidentity-pair-key/1").
 * K is deliberately not SHA-256(token), which is KyIdentity's stored `token_hash`.
 */
object PairingProof {
    const val HEADER = "KyIdentity-Pairing-Proof"
    private const val KEY = "kyidentity-pair-key/1"
    private const val REQUEST = "kyidentity-pair/1\n"
    private const val REPLY = "kyidentity-pair-reply/1\n"
    private val b64 = Base64.getUrlEncoder().withoutPadding()

    fun key(pairingToken: String): ByteArray = hmac(pairingToken.toByteArray(Charsets.UTF_8), KEY.toByteArray())

    /** The attestation credential on the proof path: `pair1:` + hex(K). */
    fun attestationCredential(pairingToken: String): String =
        "pair1:" + key(pairingToken).joinToString("") { "%02x".format(it) }

    fun requestProof(key: ByteArray, origin: String, body: ByteArray): String =
        b64.encodeToString(hmac(key, REQUEST.toByteArray() + origin.toByteArray() + "\n".toByteArray() + body))

    fun requestHash(body: ByteArray): String = b64.encodeToString(sha256(body))

    fun replyProof(key: ByteArray, origin: String, requestBody: ByteArray, responseBody: ByteArray): String =
        b64.encodeToString(
            hmac(key, (REPLY + origin + "\n" + requestHash(requestBody) + "\n").toByteArray() + responseBody),
        )

    /** Constant-time check of the reply header over the exact response bytes. */
    fun replyVerified(key: ByteArray, origin: String, requestBody: ByteArray, responseBody: ByteArray, header: String?): Boolean =
        header != null && MessageDigest.isEqual(
            replyProof(key, origin, requestBody, responseBody).toByteArray(),
            header.toByteArray(),
        )

    private fun hmac(key: ByteArray, message: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(key, "HmacSHA256")); doFinal(message) }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
}
