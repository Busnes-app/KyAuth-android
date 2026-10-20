package org.kysecurity.authenticator.pairing

import android.content.Context
import android.content.SharedPreferences
import org.kysecurity.authenticator.BuildConfig
import org.kysecurity.authenticator.pairing.PushCredential.Companion.FCM
import org.kysecurity.authenticator.pairing.PushCredential.Companion.UNIFIED_PUSH
import org.kysecurity.authenticator.security.PushKeyWrap

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

    /** This pairing's FCM push keys, or null for a pairing made before KyAuth sent them. */
    fun fcmKeys(): PushKeys? = preferences.getString("fcm_keys", null)
        ?.let { sealed -> runCatching { PushKeys.decode(String(PushKeyWrap.open(sealed), Charsets.UTF_8)) }.getOrNull() }

    /** Fresh FCM keys for a new pairing: the previous pairing's must never open this one's pushes. */
    fun newFcmKeys(): PushKeys = synchronized(LOCK) {
        PushKeys.generate().also { keys ->
            preferences.edit().putString("fcm_keys", PushKeyWrap.seal(keys.encode().toByteArray(Charsets.UTF_8))).commit()
        }
    }

    /** Keys for an FCM refresh. A pairing that has none gets them now, so the refresh upgrades it to sealed pushes. */
    fun fcmKeysForRefresh(): PushKeys = synchronized(LOCK) { fcmKeys() ?: newFcmKeys() }

    /**
     * Plaintext FCM is accepted only while KyIdentity holds no keys for this device (a pairing made
     * before KyAuth sent them, not yet refreshed). Once it does, a plaintext challenge can only
     * have been made by the relay or Firebase, so it is refused.
     */
    fun acceptsPlaintextFcm(): Boolean = registered()?.p256dh == null

    /** Records a new credential from a transport; true when KyIdentity now holds a stale one. */
    fun tokenChanged(paired: Boolean, current: PushCredential): Boolean = synchronized(LOCK) {
        preferences.edit().putCredential(latestKey(current.transport), tokenOnly(current))
            .apply { if (current.transport == UNIFIED_PUSH) remove("broken") }
            .commit()
        val stale = paired && current.transport == transport && latest(current.transport) != registered()
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
            edit.putCredential(latestKey(FCM), tokenOnly(credential))
        }
        edit.commit()
        // No usable credential for the selected transport (a switch awaiting its endpoint) stays pending too.
        preferences.edit().putBoolean("refresh_pending", latest(transport) != credential).commit()
    }

    /**
     * What KyIdentity should hold for [transport] now. The FCM token is stored alone and joined to
     * this pairing's keys here, so new keys (a keyless pairing's upgrade) make the registration stale.
     */
    private fun latest(transport: String): PushCredential? =
        if (transport == UNIFIED_PUSH) unifiedPushCredential() else preferences.credential(latestKey(FCM))?.withKeys(fcmKeys())

    private fun tokenOnly(credential: PushCredential) = if (credential.transport == FCM) credential.withKeys(null) else credential

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
