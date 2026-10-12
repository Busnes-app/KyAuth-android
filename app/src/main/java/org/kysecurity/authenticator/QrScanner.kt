package org.kysecurity.authenticator

enum class ScanPurpose { PAIRING, TOTP }

/**
 * One QR scan. The channel's scanner reports `(purpose, text)` to the callback given at creation:
 * text, or null if scanning failed; a cancelled scan reports nothing. The purpose survives activity
 * recreation, so a result never reaches a callback that no longer knows what it was for.
 */
fun interface QrScanner {
    fun scan(purpose: ScanPurpose)
}
