package org.kysecurity.authenticator

import androidx.activity.ComponentActivity
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning

/** ML Kit: the camera runs in Play Services, so this build needs no CAMERA permission. */
object ChannelQrScanner {
    fun create(activity: ComponentActivity, onResult: (ScanPurpose, String?) -> Unit) = QrScanner { purpose ->
        GmsBarcodeScanning.getClient(activity).startScan()
            .addOnSuccessListener { onResult(purpose, it.rawValue.orEmpty()) }
            .addOnFailureListener { onResult(purpose, null) }
    }
}
