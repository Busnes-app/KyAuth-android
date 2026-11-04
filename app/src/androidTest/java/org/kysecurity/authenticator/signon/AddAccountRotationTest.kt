package org.kysecurity.authenticator.signon

import android.accounts.AccountAuthenticatorResponse
import android.content.Context
import android.content.Intent
import android.os.Binder
import android.os.Parcel
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.authenticator.MainActivity
import org.kysecurity.authenticator.ShowOverKeyguard

@RunWith(AndroidJUnit4::class)
class AddAccountRotationTest {
    @get:Rule val showOverKeyguard = ShowOverKeyguard()

    private class Spy : Binder() {
        val calls = AtomicInteger()
        val called = CountDownLatch(1)
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            calls.incrementAndGet()
            called.countDown()
            return true
        }

        fun response(): AccountAuthenticatorResponse {
            val parcel = Parcel.obtain()
            try {
                parcel.writeStrongBinder(this)
                parcel.setDataPosition(0)
                return AccountAuthenticatorResponse(parcel)
            } finally {
                parcel.recycle()
            }
        }
    }

    // The nonce is single-use, so the recreated activity must keep the response it already took.
    @Test
    fun rotationKeepsTheCallerAnsweredOnce() {
        val caller = Spy()
        val context = ApplicationProvider.getApplicationContext<Context>()
        val intent = Intent(context, MainActivity::class.java)
            .putExtra(MainActivity.EXTRA_ADD_ACCOUNT, PendingAddAccount.issue(caller.response()))
        ActivityScenario.launch<MainActivity>(intent).use { scenario ->
            scenario.recreate()
            assertEquals(0, caller.calls.get())
        }
        // Closing without pairing cancels: the caller hears exactly once.
        assertTrue(caller.called.await(10, TimeUnit.SECONDS))
        assertEquals(1, caller.calls.get())
    }
}
