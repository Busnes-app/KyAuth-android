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
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.authenticator.BuildConfig

// Shared state invariants run on every available transport; FCM-only workflows are explicit.
@RunWith(AndroidJUnit4::class)
class PushStoreTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val a = PushCredential(PushCredential.FCM, "token-a")
    private val b = PushCredential(PushCredential.FCM, "token-b")
    private val transports = if (BuildConfig.HAS_FCM) listOf(PushCredential.FCM, PushCredential.UNIFIED_PUSH)
        else listOf(PushCredential.UNIFIED_PUSH)

    private fun credential(transport: String, token: String) = if (transport == PushCredential.FCM)
        PushCredential(transport, token) else PushCredential(transport, "https://push.example.net/$token", "p256dh", "auth")

    private fun storeFor(transport: String): PushStore {
        reset()
        return PushStore(context).apply { this.transport = transport }
    }

    @Before @After fun reset() {
        context.deleteSharedPreferences("push")
    }

    @Test fun rotationDuringARefreshStaysPending() {
        for (transport in transports) {
            val store = storeFor(transport)
            val first = credential(transport, "token-a")
            val second = credential(transport, "token-b")
            store.markRegistered(credential(transport, "token-0"))
            assertTrue(store.tokenChanged(paired = true, first)) // refresh for A starts
            assertTrue(store.tokenChanged(paired = true, second)) // B lands before A's 2xx
            store.markRegistered(first)
            assertEquals(first, store.registered())
            assertTrue(store.refreshPending())
        }
    }

    @Test fun acknowledgingTheLatestClearsPending() {
        for (transport in transports) {
            val store = storeFor(transport)
            val latest = credential(transport, "token-b")
            store.markRegistered(credential(transport, "token-0"))
            store.tokenChanged(paired = true, latest)
            store.markRegistered(latest)
            assertFalse(store.refreshPending())
        }
    }

    @Test fun firstRegistrationIsNotPending() {
        for (transport in transports) {
            val store = storeFor(transport)
            val first = credential(transport, "token-a")
            // UnifiedPush's first endpoint arrives from its distributor, never from an ack.
            if (transport == PushCredential.UNIFIED_PUSH) store.tokenChanged(paired = false, first)
            store.markRegistered(first)
            assertFalse(store.refreshPending())
        }
    }

    @Test fun switchAwaitingItsEndpointStaysPending() {
        assumeTrue("FCM switching is absent from this build", BuildConfig.HAS_FCM)
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
        assumeTrue("FCM pairing is absent from this build", BuildConfig.HAS_FCM)
        val store = PushStore(context)
        val keys = store.newFcmKeys()
        store.markRegistered(a.withKeys(keys))
        assertFalse(store.refreshPending())
        assertFalse(store.acceptsPlaintextFcm())
        assertFalse(store.tokenChanged(paired = true, a)) // onNewToken hands the token alone
        assertTrue(store.tokenChanged(paired = true, b))
    }

    @Test fun keylessPairingUpgradesOnItsNextRefresh() {
        assumeTrue("Legacy FCM pairing is absent from this build", BuildConfig.HAS_FCM)
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
        if (BuildConfig.HAS_FCM) store.transport = PushCredential.FCM
        store.forgetUnifiedPush() // "Use Firebase"
        store.transport = PushCredential.UNIFIED_PUSH // and back, awaiting a fresh endpoint
        store.markRegistered(up) // the old refresh's 2xx lands
        assertEquals(null, store.unifiedPushCredential())
        assertTrue(store.refreshPending())
    }
}
