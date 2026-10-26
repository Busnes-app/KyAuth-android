package org.kysecurity.authenticator

import org.kysecurity.authenticator.mfa.MfaChallenge
import org.kysecurity.authenticator.pairing.PairedAccount
import org.kysecurity.authenticator.totp.TotpEntry
import java.util.UUID
import kotlin.random.Random

/**
 * Store-review demo for an unpaired install. Everything here is fixed or in memory: no network,
 * no vault, no Keystore. `.invalid` (RFC 2606) can never resolve.
 */
object DemoMode {
    const val PUSH_INTERVAL_MS = 15_000L
    const val PUSH_LIFETIME_MS = 60_000L

    val account = PairedAccount(
        serverUrl = "https://demo.kyidentity.invalid",
        deviceId = "demo",
        deviceName = "Demo device",
        username = "demo@example.com",
    )

    /** A paired install never runs the demo. */
    fun active(requested: Boolean, paired: PairedAccount?) = requested && paired == null

    fun entries() = listOf(
        TotpEntry(title = "Example Mail", secretBase32 = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", url = "https://mail.example.com", id = "demo-mail"),
        TotpEntry(title = "Example Cloud", secretBase32 = "KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU", url = "https://cloud.example.com", id = "demo-cloud"),
        TotpEntry(title = "Example Bank", secretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", notes = "Demo account", id = "demo-bank"),
    )

    fun challenge(nowMs: Long, random: Random = Random.Default): MfaChallenge {
        val numbers = (10..99).shuffled(random).take(4).map { it.toString() }
        return MfaChallenge(
            challengeId = "demo-${UUID.randomUUID()}",
            matchDigits = numbers.first(),
            decoyDigits = numbers.drop(1),
            serverUrl = account.serverUrl,
            username = account.username,
            purpose = "login",
            expiresAtEpochMs = nowMs + PUSH_LIFETIME_MS,
        )
    }
}
