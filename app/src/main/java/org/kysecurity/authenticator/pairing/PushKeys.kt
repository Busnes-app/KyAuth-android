package org.kysecurity.authenticator.pairing

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.util.Base64

/**
 * This pairing's RFC 8291 keys for FCM, made on the phone. KyIdentity gets the public key and the
 * auth secret and seals every FCM push to them, so the push relay and Google see only ciphertext.
 * (UnifiedPush keys are the connector's own; these are only for FCM.)
 */
class PushKeys(val privateKey: ECPrivateKey, val publicPoint: ByteArray, val authSecret: ByteArray) {
    init {
        require(publicPoint.size == 65 && publicPoint[0] == UNCOMPRESSED) { "p256dh must be an uncompressed P-256 point" }
        require(authSecret.size == 16) { "auth must be 16 bytes" }
    }

    /** `pushP256dh` and `pushAuth`: base64url without padding, as KyIdentity and KyAuth iOS use. */
    val p256dh: String get() = b64(publicPoint)
    val auth: String get() = b64(authSecret)

    /** The `push` prefs form: the 32-byte private scalar, p256dh and auth, base64url, joined by '.'. */
    fun encode(): String = listOf(b64(scalar(privateKey)), p256dh, auth).joinToString(".")

    // These open this pairing's pushes: never log them.
    override fun toString(): String = "PushKeys(<redacted>)"

    companion object {
        private const val UNCOMPRESSED: Byte = 4

        /** P-256, taken from a generated key: the one source that works on every JVM and Android provider. */
        val P256: ECParameterSpec by lazy {
            val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            (pair.public as ECPublicKey).params
        }

        fun generate(random: SecureRandom = SecureRandom()): PushKeys {
            val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1"), random) }.generateKeyPair()
            val secret = ByteArray(16).also(random::nextBytes)
            return PushKeys(pair.private as ECPrivateKey, point(pair.public as ECPublicKey), secret)
        }

        /** [encode]'s form back, or null for anything else. */
        fun decode(stored: String?): PushKeys? = runCatching {
            val parts = stored!!.split('.')
            require(parts.size == 3)
            fromScalar(unb64(parts[0]), parts[1], parts[2])
        }.getOrNull()

        /** From a raw 32-byte private scalar, the form RFC 8291's example and KyAuth iOS use. */
        fun fromScalar(scalar: ByteArray, p256dh: String, auth: String): PushKeys {
            require(scalar.size == 32) { "Private key must be 32 bytes" }
            val private = KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(1, scalar), P256)) as ECPrivateKey
            val point = unb64(p256dh)
            publicKey(point) // refuse a point off the curve
            return PushKeys(private, point, unb64(auth))
        }

        /** An uncompressed P-256 point as a public key; refuses anything not on the curve. */
        fun publicKey(point: ByteArray): ECPublicKey {
            require(point.size == 65 && point[0] == UNCOMPRESSED) { "Not an uncompressed P-256 point" }
            val x = BigInteger(1, point.copyOfRange(1, 33))
            val y = BigInteger(1, point.copyOfRange(33, 65))
            val p = (P256.curve.field as ECFieldFp).p
            require(x < p && y < p) { "Point coordinate out of range" }
            val rhs = x.pow(3).add(P256.curve.a.multiply(x)).add(P256.curve.b).mod(p)
            require(y.multiply(y).mod(p) == rhs) { "Point is not on P-256" }
            return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), P256)) as ECPublicKey
        }

        fun point(key: ECPublicKey): ByteArray =
            byteArrayOf(UNCOMPRESSED) + fixed32(key.w.affineX) + fixed32(key.w.affineY)

        private fun scalar(key: ECPrivateKey): ByteArray = fixed32(key.s)

        private fun fixed32(value: BigInteger): ByteArray {
            val bytes = value.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
            require(bytes.size <= 32) { "Value exceeds 32 bytes" }
            return ByteArray(32 - bytes.size) + bytes
        }

        fun b64(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        /** base64url, with or without padding. */
        fun unb64(value: String): ByteArray = Base64.getUrlDecoder().decode(value)
    }
}
