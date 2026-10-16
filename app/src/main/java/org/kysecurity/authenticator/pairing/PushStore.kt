package org.kysecurity.authenticator.pairing

import android.content.Context
import android.content.SharedPreferences
import org.kysecurity.authenticator.BuildConfig
import org.kysecurity.authenticator.pairing.PushCredential.Companion.FCM
import org.kysecurity.authenticator.pairing.PushCredential.Companion.UNIFIED_PUSH

/** Push delivery state (prefs "push"). The registered credential is only what KyIdentity acknowledged with a 2xx. */
class PushStore(context: Context) {
    private val preferences = context.getSharedPreferences("push", Context.MODE_PRIVATE)

    var transport: String
        get() = if (!BuildConfig.HAS_FCM) UNIFIED_PUSH else preferences.getString("transport", null) ?: FCM
        set(value) {
            require(value == UNIFIED_PUSH || (value == FCM && BuildConfig.HAS_FCM)) { "Transport unavailable in this build" }
            preferences.edit().putString("transport", value).remove("broken").apply()
        }

    /** The distributor's latest endpoint, or null when there is none or delivery broke since. */
    fun unifiedPushCredential(): PushCredential? =
        if (broken() != null) null else preferences.credential("up")

    fun registered(): PushCredential? = preferences.credential("registered")

    fun refreshPending(): Boolean = preferences.getBoolean("refresh_pending", false)

    fun broken(): String? = preferences.getString("broken", null)

    /** Records a new credential from a transport; true when KyIdentity now holds a stale one. */
    fun tokenChanged(paired: Boolean, current: PushCredential): Boolean = synchronized(LOCK) {
        preferences.edit().putCredential(latestKey(current.transport), current)
            .apply { if (current.transport == UNIFIED_PUSH) remove("broken") }
            .commit()
        val stale = paired && current.transport == transport && current != registered()
        if (stale) markRefreshPending()
        stale
    }

    fun markRefreshPending() = preferences.edit().putBoolean("refresh_pending", true).apply()

    /** UnifiedPush stopped: the endpoint is no longer trusted until a new one arrives. */
    fun markBroken(reason: String) = preferences.edit().putString("broken", reason).apply()

    /**
     * KyIdentity acknowledged [credential]. Pending clears only if it is still the selected
     * transport's latest: a rotation or transport switch that landed mid-request stays pending.
     */
    fun markRegistered(credential: PushCredential): Unit = synchronized(LOCK) {
        val edit = preferences.edit().putCredential("registered", credential)
        // An FCM token can come from getToken() at pairing with no onNewToken, so the first one
        // acknowledged seeds it. A UnifiedPush endpoint only ever comes from onNewEndpoint: an
        // acknowledgement must never restore one that forgetUnifiedPush retired.
        if (credential.transport == FCM && preferences.credential(latestKey(FCM)) == null) {
            edit.putCredential(latestKey(FCM), credential)
        }
        edit.commit()
        // No usable credential for the selected transport (a switch awaiting its endpoint) stays pending too.
        val latest = if (transport == UNIFIED_PUSH) unifiedPushCredential() else preferences.credential(latestKey(FCM))
        preferences.edit().putBoolean("refresh_pending", latest != credential).commit()
    }

    /** The connector deleted this registration's keys: its endpoint must not be sent again. */
    fun forgetUnifiedPush(): Unit = synchronized(LOCK) {
        preferences.edit().putCredential(latestKey(UNIFIED_PUSH), null).commit()
    }

    /** The FCM token was deleted: the next one is fetched fresh and seeded by [markRegistered]. */
    fun forgetFcm(): Unit = synchronized(LOCK) {
        preferences.edit().putCredential(latestKey(FCM), null).commit()
    }

    fun forgetRegistration() = preferences.edit()
        .putCredential("registered", null)
        .remove("refresh_pending")
        .apply()

    private fun latestKey(transport: String) = if (transport == UNIFIED_PUSH) "up" else "fcm"

    private fun SharedPreferences.credential(prefix: String): PushCredential? = runCatching {
        PushCredential(
            getString("${prefix}_transport", null)!!,
            getString("${prefix}_token", null)!!,
            getString("${prefix}_p256dh", null),
            getString("${prefix}_auth", null),
        )
    }.getOrNull()

    private fun SharedPreferences.Editor.putCredential(prefix: String, credential: PushCredential?) = this
        .putString("${prefix}_transport", credential?.transport)
        .putString("${prefix}_token", credential?.token)
        .putString("${prefix}_p256dh", credential?.p256dh)
        .putString("${prefix}_auth", credential?.auth)

    private companion object {
        // Services and the activity write from different threads; reconcile must see one state.
        val LOCK = Any()
    }
}
