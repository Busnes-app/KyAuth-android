package org.kysecurity.authenticator

import android.os.Bundle
import com.journeyapps.barcodescanner.CaptureActivity
import org.kysecurity.authenticator.security.secureWindow

/** zxing's scanner in its own window: the preview shows TOTP secrets and pairing credentials. */
class SecureCaptureActivity : CaptureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        secureWindow(window)
        super.onCreate(savedInstanceState)
    }
}
