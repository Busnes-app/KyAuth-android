package org.kysecurity.authenticator.pairing

import org.junit.Assert.assertEquals
import org.junit.Test
import org.kysecurity.authenticator.R

class AttestationSummaryTest {
    private val strings = mapOf(
        R.string.attested_strongbox to "SB",
        R.string.attested_tee to "TEE",
        R.string.attested_none to "NONE",
        R.string.attested_none_server to "SERVER",
        R.string.attested_none_keystore to "KEYSTORE",
        R.string.attested_none_refused to "REFUSED",
        R.string.boot_locked to "LOCKED",
        R.string.boot_locked_custom_os to "CUSTOM",
        R.string.boot_unlocked to "UNLOCKED",
    )

    @Test
    fun everyLevelAndBootStateCombination() {
        val levels = mapOf("none" to "NONE", "tee" to "TEE", "strongbox" to "SB")
        val boots = mapOf("unknown" to null, "locked-verified" to "LOCKED", "locked-selfsigned" to "CUSTOM", "unlocked" to "UNLOCKED")
        for ((level, levelText) in levels) for ((boot, bootText) in boots) {
            val expected = if (bootText == null) levelText else "$levelText\n$bootText"
            assertEquals("$level/$boot", expected, attestationSummary(level, boot, "") { strings.getValue(it) })
        }
    }

    @Test
    fun noneHintFollowsReason() {
        val expected = mapOf(
            "" to "NONE", AttestationReason.SERVER_UNSUPPORTED to "SERVER",
            AttestationReason.KEYSTORE_SOFTWARE to "KEYSTORE", AttestationReason.NOT_ACCEPTED to "REFUSED",
        )
        for ((reason, text) in expected) assertEquals(reason, text, attestationSummary("none", "unknown", reason) { strings.getValue(it) })
        assertEquals("TEE", attestationSummary("tee", "unknown", AttestationReason.NOT_ACCEPTED) { strings.getValue(it) })
    }
}
