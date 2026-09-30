package org.kysecurity.authenticator.pairing

import org.kysecurity.authenticator.R

/** Settings text for the attested level, with the boot state as a second line when known. */
fun attestationSummary(level: String, bootState: String, reason: String, string: (Int) -> String): String {
    val attestation = when (level) {
        "strongbox" -> string(R.string.attested_strongbox)
        "tee" -> string(R.string.attested_tee)
        else -> when (reason) {
            AttestationReason.SERVER_UNSUPPORTED -> string(R.string.attested_none_server)
            AttestationReason.KEYSTORE_SOFTWARE -> string(R.string.attested_none_keystore)
            AttestationReason.NOT_ACCEPTED -> string(R.string.attested_none_refused)
            else -> string(R.string.attested_none)
        }
    }
    val boot = when (bootState) {
        "locked-verified" -> string(R.string.boot_locked)
        "locked-selfsigned" -> string(R.string.boot_locked_custom_os)
        "unlocked" -> string(R.string.boot_unlocked)
        else -> ""
    }
    return listOf(attestation, boot).filter { it.isNotEmpty() }.joinToString("\n")
}
