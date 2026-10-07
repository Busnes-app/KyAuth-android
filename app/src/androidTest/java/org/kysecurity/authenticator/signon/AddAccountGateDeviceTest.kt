package org.kysecurity.authenticator.signon

import android.accounts.AccountManager
import android.accounts.AuthenticatorException
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AddAccountGateDeviceTest {
    // The test runs as KyAuth's own UID: neither system Settings nor a pinned consumer.
    @Test
    fun addAccountFromAnUnpinnedAppIsRefused() {
        val future = AccountManager.get(ApplicationProvider.getApplicationContext())
            .addAccount(KyIdentityAccount.TYPE, null, null, null, null, null, null)
        val error = assertThrows(AuthenticatorException::class.java) { future.getResult(10, TimeUnit.SECONDS) }
        assertTrue(error.cause is UnsupportedOperationException)
    }
}
