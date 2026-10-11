package org.kysecurity.authenticator

import android.os.Bundle
import androidx.activity.ComponentActivity
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

/**
 * zxing, in its own activity. Call from onCreate: registerForActivityResult is refused once
 * STARTED. The purpose is kept in saved state, because the activity that launched the scan may
 * be recreated before the result comes back.
 */
object ChannelQrScanner {
    private const val STATE_KEY = "kyauth_qr_scan_purpose"

    fun create(activity: ComponentActivity, onResult: (ScanPurpose, String?) -> Unit): QrScanner {
        val registry = activity.savedStateRegistry
        var purpose = registry.consumeRestoredStateForKey(STATE_KEY)?.getString(STATE_KEY)
            ?.let { runCatching { ScanPurpose.valueOf(it) }.getOrNull() }
        registry.registerSavedStateProvider(STATE_KEY) { Bundle().apply { putString(STATE_KEY, purpose?.name) } }
        val launcher = activity.registerForActivityResult(ScanContract()) { result ->
            val scanned = purpose ?: return@registerForActivityResult
            purpose = null
            // null contents is a cancelled scan.
            result.contents?.let { onResult(scanned, it) }
        }
        return QrScanner {
            purpose = it
            launcher.launch(options())
        }
    }

    internal fun options(): ScanOptions = ScanOptions()
        .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
        .setBeepEnabled(false)
        .setOrientationLocked(false)
        .setCaptureActivity(SecureCaptureActivity::class.java)
}
