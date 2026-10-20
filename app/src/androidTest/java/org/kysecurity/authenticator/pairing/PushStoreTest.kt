package org.kysecurity.authenticator.pairing

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

// Runs on the play flavor (CI), where FCM is the default transport.
@RunWith(AndroidJUnit4::class)
class PushStoreTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val a = PushCredential(PushCredential.FCM, "token-a")
    private val b = PushCredential(PushCredential.FCM, "token-b")

    @Before @After fun reset() {
        context.deleteSharedPreferences("push")
    }

    @Test fun rotationDuringARefreshStaysPending() {
        val store = PushStore(context)
        store.markRegistered(PushCredential(PushCredential.FCM, "token-0"))
        assertTrue(store.tokenChanged(paired = true, a)) // refresh for A starts
        assertTrue(store.tokenChanged(paired = true, b)) // B lands before A's 2xx
        store.markRegistered(a)
        assertEquals(a, store.registered())
        assertTrue(store.refreshPending())
    }

    @Test fun acknowledgingTheLatestClearsPending() {
        val store = PushStore(context)
        store.markRegistered(PushCredential(PushCredential.FCM, "token-0"))
        store.tokenChanged(paired = true, b)
        store.markRegistered(b)
        assertFalse(store.refreshPending())
    }

    @Test fun firstRegistrationIsNotPending() {
        val store = PushStore(context)
        store.markRegistered(a)
        assertFalse(store.refreshPending())
    }

    @Test fun switchAwaitingItsEndpointStaysPending() {
        val store = PushStore(context)
        store.markRegistered(PushCredential(PushCredential.FCM, "token-0"))
        store.tokenChanged(paired = true, a) // FCM refresh for A starts
        store.transport = PushCredential.UNIFIED_PUSH // switched; no endpoint yet
        store.markRegistered(a)
        assertTrue(store.refreshPending())
    }

    @Test fun fcmKeysSurviveStorageAndAreFreshPerPairing() {
        val store = PushStore(context)
        assertEquals(null, store.fcmKeys())
        val first = store.newFcmKeys()
        assertEquals(first.p256dh, PushStore(context).fcmKeys()?.p256dh)
        assertEquals(first.auth, PushStore(context).fcmKeys()?.auth)
        assertEquals(first.p256dh, store.fcmKeysForRefresh().p256dh) // a refresh reuses this pairing's keys
        assertNotEquals(first.p256dh, store.newFcmKeys().p256dh)
    }

    @Test fun keyedPairingRefusesPlaintextAndIsNotStaleForItsOwnToken() {
        val store = PushStore(context)
        val keys = store.newFcmKeys()
        store.markRegistered(a.withKeys(keys))
        assertFalse(store.refreshPending())
        assertFalse(store.acceptsPlaintextFcm())
        assertFalse(store.tokenChanged(paired = true, a)) // onNewToken hands the token alone
        assertTrue(store.tokenChanged(paired = true, b))
    }

    @Test fun keylessPairingUpgradesOnItsNextRefresh() {
        val store = PushStore(context)
        store.markRegistered(a) // paired before KyAuth sent FCM keys
        assertTrue(store.acceptsPlaintextFcm())
        assertFalse(store.tokenChanged(paired = true, a))
        val keys = store.fcmKeysForRefresh() // the refresh makes keys...
        assertTrue(store.acceptsPlaintextFcm()) // ...but KyIdentity has not taken them yet
        store.markRegistered(a.withKeys(keys)) // its 2xx
        assertEquals(keys.p256dh, store.registered()?.p256dh)
        assertFalse(store.refreshPending())
        assertFalse(store.acceptsPlaintextFcm())
    }

    @Test fun forgottenUnifiedPushEndpointIsNotReused() {
        val store = PushStore(context)
        val up = PushCredential(PushCredential.UNIFIED_PUSH, "https://push.example.net/up", "p256dh", "auth")
        store.tokenChanged(paired = false, up)
        assertEquals(up, store.unifiedPushCredential())
        store.forgetUnifiedPush()
        assertEquals(null, store.unifiedPushCredential())
    }

    @Test fun lateAcknowledgementDoesNotRestoreARetiredEndpoint() {
        val store = PushStore(context)
        val up = PushCredential(PushCredential.UNIFIED_PUSH, "https://push.example.net/up", "p256dh", "auth")
        store.transport = PushCredential.UNIFIED_PUSH
        store.tokenChanged(paired = true, up) // refresh for up starts
        store.transport = PushCredential.FCM
        store.forgetUnifiedPush() // "Use Firebase"
        store.transport = PushCredential.UNIFIED_PUSH // and back, awaiting a fresh endpoint
        store.markRegistered(up) // the old refresh's 2xx lands
        assertEquals(null, store.unifiedPushCredential())
        assertTrue(store.refreshPending())
    }
}
