package org.kysecurity.authenticator.totp

import java.util.UUID

/** One TOTP account, stored in [TotpVault]. */
data class TotpEntry(
    val title: String,
    val secretBase32: String,
    val digits: Int = 6,
    val periodSeconds: Long = 30,
    val algorithm: Algorithm = Algorithm.SHA1,
    val issuer: String? = null,
    val url: String? = null,
    val notes: String? = null,
    val id: String = UUID.randomUUID().toString(),
) {
    init {
        require(title.isNotBlank())
        require(digits in 6..8)
        require(periodSeconds > 0)
        require(secretBase32.isNotBlank())
        require(TotpGenerator.isUsableSecret(secretBase32)) { "TOTP secret is not usable Base32" }
    }

    enum class Algorithm { SHA1, SHA256, SHA512 }
}
