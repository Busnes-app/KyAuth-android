package org.kysecurity.authenticator.signon

import android.accounts.AccountAuthenticatorResponse
import android.accounts.AccountManager
import android.content.Context
import android.content.Intent
import android.os.Binder
import android.os.Parcel
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.authenticator.pairing.PairedAccount

@RunWith(AndroidJUnit4::class)
class SignOnResponseBindingTest {
    /** Counts every call made on the response it backs. */
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

    // A launch holding a live nonce cannot redirect the answer to a response it supplies.
    @Test
    fun answerGoesToTheBoundResponseNotTheExtra() {
        val bound = Spy()
        val injected = Spy()
        val request = SignOnRequest.Proceed(
            TrustedCaller("org.kysecurity.mail", "KyPost"), "kypost", "https://mail.example.com",
            PairedAccount("https://id.example.com", "d", "P", "alice", "u1", canSignOn = true),
        )
        val nonce = PendingSignOn.issue(SignOnHandoff(request, bound.response()))
        val context = ApplicationProvider.getApplicationContext<Context>()
        context.startActivity(
            Intent(context, SignOnActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                .putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, injected.response())
                .putExtra(SignOnActivity.EXTRA_REQUEST, nonce),
        )
        // The test install is unpaired, so the activity answers at once with "pair first".
        assertTrue(bound.called.await(10, TimeUnit.SECONDS))
        assertEquals(0, injected.calls.get())
    }
}
