package org.kysecurity.authenticator.security

import android.view.Window
import android.view.WindowManager
import org.kysecurity.authenticator.BuildConfig

/** Keeps a window out of screenshots, recordings and the recents thumbnail unless the build allows capture. */
fun secureWindow(window: Window, allowScreenshots: Boolean = BuildConfig.ALLOW_SCREENSHOTS) {
    if (!allowScreenshots) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
}
