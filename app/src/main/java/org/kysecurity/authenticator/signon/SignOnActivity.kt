package org.kysecurity.authenticator.signon

import androidx.appcompat.app.AppCompatActivity

class SignOnActivity : AppCompatActivity() {
    companion object {
        const val EXTRA_CLIENT_ID = "client_id"
        const val EXTRA_CALLER_LABEL = "caller_label"
        const val EXTRA_CALLER_PACKAGE = "caller_package"
    }
}
