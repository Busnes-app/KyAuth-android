package org.kysecurity.authenticator.signon

import android.app.Service
import android.content.Intent
import android.os.IBinder

class KyIdentityAuthenticatorService : Service() {
    private val authenticator by lazy { KyIdentityAuthenticator(this) }
    override fun onBind(intent: Intent?): IBinder? = authenticator.iBinder
}
