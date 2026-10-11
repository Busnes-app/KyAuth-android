package org.kysecurity.authenticator

import org.junit.Assert.assertEquals
import org.junit.Test

class ChannelQrScannerTest {
    @Test fun scansInTheSecureCaptureActivity() {
        assertEquals(SecureCaptureActivity::class.java, ChannelQrScanner.options().captureActivity)
    }
}
