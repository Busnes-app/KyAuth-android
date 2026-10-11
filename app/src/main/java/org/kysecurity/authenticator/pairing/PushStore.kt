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
    fun tokenChanged(paired: Boolean, current: PushCredential): Boolean {
        if (current.transport == UNIFIED_PUSH) {
            preferences.edit().putCredential("up", current).remove("broken").apply()
        }
        val stale = paired && current.transport == transport && current != registered()
        if (stale) markRefreshPending()
        return stale
    }

    fun markRefreshPending() = preferences.edit().putBoolean("refresh_pending", true).apply()

    /** UnifiedPush stopped: the endpoint is no longer trusted until a new one arrives. */
    fun markBroken(reason: String) = preferences.edit().putString("broken", reason).apply()

    fun markRegistered(credential: PushCredential) = preferences.edit()
        .putCredential("registered", credential)
        .remove("refresh_pending")
        .apply()

    fun forgetRegistration() = preferences.edit()
        .putCredential("registered", null)
        .remove("refresh_pending")
        .apply()

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
}
