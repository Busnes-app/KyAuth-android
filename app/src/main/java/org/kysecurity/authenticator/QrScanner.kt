package org.kysecurity.authenticator

/** One QR scan. [onResult] gets the text, or null if scanning failed; a cancelled scan reports nothing. */
fun interface QrScanner {
    fun scan(onResult: (String?) -> Unit)
}
