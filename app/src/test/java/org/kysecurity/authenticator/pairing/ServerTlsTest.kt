package org.kysecurity.authenticator.pairing

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.EllipticCurve
import java.security.spec.RSAPublicKeySpec

class ServerTlsTest {
    @Test fun literalRsaBitsDecideTheFloor() {
        for (bits in listOf(1024, 2047, 2048, 4096)) {
            val modulus = BigInteger.ONE.shiftLeft(bits - 1).add(BigInteger.valueOf(3))
            val key = KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(modulus, BigInteger.valueOf(65537)))
            if (bits >= 2048) assertTrue(ServerTls.meetsFloor(key)) else assertFalse(ServerTls.meetsFloor(key))
        }
    }

    @Test fun strongNativeEcKeysRemainUsable() {
        for (curve in listOf("secp256r1", "secp384r1", "secp521r1")) {
            val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec(curve)) }.generateKeyPair().public
            assertTrue(curve, ServerTls.meetsFloor(key))
        }
    }

    @Test fun undersizedEcMetadataIsRefused() {
        val original = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public as ECPublicKey
        // Predicate-only metadata control; native fixtures separately prove actual handshake behavior.
        val field = ECFieldFp(BigInteger.ONE.shiftLeft(224).subtract(BigInteger.valueOf(17)))
        val params = ECParameterSpec(EllipticCurve(field, BigInteger.ONE, BigInteger.ONE), original.params.generator, original.params.order, 1)
        val undersized = object : ECPublicKey by original { override fun getParams() = params }
        assertFalse(ServerTls.meetsFloor(undersized))
    }

    @Test fun unrecognizedKeysAreRefused() {
        val unknown = object : PublicKey {
            override fun getAlgorithm() = "unknown"
            override fun getFormat() = "X.509"
            override fun getEncoded() = byteArrayOf()
        }
        assertFalse(ServerTls.meetsFloor(unknown))
    }
}
