package org.kysecurity.authenticator.mfa

import com.google.crypto.tink.subtle.Hkdf
import org.kysecurity.authenticator.pairing.PushKeys
import java.nio.ByteBuffer
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** RFC 8291 decryption for sealed FCM pushes; the same construction as KyAuth iOS `WebPush.decrypt`. */
object WebPush {
    // RFC 8188 header: 16-byte salt, 4-byte record size, 1-byte key length, 65-byte sender key.
    private const val HEADER = 86

    /** Opens an RFC 8291 aes128gcm body with exactly one record; throws on anything else. */
    fun decrypt(body: ByteArray, keys: PushKeys): ByteArray {
        require(body.size >= HEADER + 17 && body[20].toInt() == 65) { "Not an aes128gcm body" }
        val salt = body.copyOfRange(0, 16)
        val recordSize = ByteBuffer.wrap(body, 16, 4).int.toLong() and 0xFFFFFFFFL
        val senderKey = body.copyOfRange(21, HEADER)
        val record = body.copyOfRange(HEADER, body.size)
        require(recordSize >= 18 && record.size <= recordSize) { "More than one record" }

        val shared = KeyAgreement.getInstance("ECDH").run {
            init(keys.privateKey)
            doPhase(PushKeys.publicKey(senderKey), true)
            generateSecret()
        }
        val ikm = hkdf(keys.authSecret, shared, "WebPush: info\u0000".toByteArray() + keys.publicPoint + senderKey, 32)
        val cek = hkdf(salt, ikm, "Content-Encoding: aes128gcm\u0000".toByteArray(), 16)
        val nonce = hkdf(salt, ikm, "Content-Encoding: nonce\u0000".toByteArray(), 12)
        val padded = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(cek, "AES"), GCMParameterSpec(128, nonce))
            doFinal(record)
        }
        // Zero padding follows the last-record delimiter 0x02.
        val end = padded.indexOfLast { it != 0.toByte() }
        require(end >= 0 && padded[end] == 2.toByte()) { "Not a last record" }
        return padded.copyOf(end)
    }

    /** RFC 5869 HKDF-SHA256. */
    private fun hkdf(salt: ByteArray, ikm: ByteArray, info: ByteArray, length: Int): ByteArray =
        Hkdf.computeHkdf("HMACSHA256", ikm, salt, info, length)
}
