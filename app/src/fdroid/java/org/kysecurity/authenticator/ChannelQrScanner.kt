package org.kysecurity.authenticator

import androidx.activity.ComponentActivity
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

/** zxing, in-process. Call from onCreate: registerForActivityResult is refused once STARTED. */
object ChannelQrScanner {
    fun create(activity: ComponentActivity): QrScanner {
        var pending: ((String?) -> Unit)? = null
        val launcher = activity.registerForActivityResult(ScanContract()) { result ->
            val callback = pending
            pending = null
            // null contents is a cancelled scan.
            result.contents?.let { callback?.invoke(it) }
        }
        return QrScanner { onResult ->
            pending = onResult
            launcher.launch(ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE).setBeepEnabled(false).setOrientationLocked(false))
        }
    }
}
