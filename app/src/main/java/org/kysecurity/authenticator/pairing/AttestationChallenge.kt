package org.kysecurity.authenticator.pairing

import java.security.MessageDigest

/**
 * The attestation challenge for a pairing. Derived from the credential the phone presents, so
 * KyIdentity recomputes it from the registration request without another round trip.
 */
object AttestationChallenge {
    private const val PREFIX = "kyidentity-attest-v1|"

    internal fun credential(pairing: QrPairing): String =
        pairing.pairingToken?.takeIf { it.isNotBlank() } ?: "${pairing.userId}|${pairing.pinCode}"

    fun forPairing(pairing: QrPairing): ByteArray =
        MessageDigest.getInstance("SHA-256").digest((PREFIX + credential(pairing)).toByteArray(Charsets.UTF_8))
}
