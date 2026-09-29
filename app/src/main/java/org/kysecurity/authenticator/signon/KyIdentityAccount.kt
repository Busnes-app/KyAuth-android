package org.kysecurity.authenticator.signon

import android.accounts.Account
import android.accounts.AccountManager
import android.content.Context
import android.os.Bundle
import org.kysecurity.authenticator.pairing.PairedAccount

/** The system account KyAuth publishes for a paired device that may sign in to suite apps. */
object KyIdentityAccount {
    const val TYPE = "org.kysecurity.identity"
    const val KEY_SERVER_URL = "server_url"
    const val KEY_USER_ID = "user_id"
    const val KEY_DEVICE_ID = "device_id"

    fun current(context: Context): Account? =
        AccountManager.get(context).getAccountsByType(TYPE).firstOrNull()

    /** Makes the system account match the pairing: present iff the device can sign on. */
    fun sync(context: Context, account: PairedAccount?): Boolean {
        val am = AccountManager.get(context)
        val existing = am.getAccountsByType(TYPE)
        val userId = account?.userId
        if (account == null || !account.canSignOn || userId.isNullOrBlank()) {
            existing.forEach { am.removeAccountExplicitly(it) }
            return true
        }
        val name = account.username?.takeIf { it.isNotBlank() } ?: userId
        val wanted = Account(name, TYPE)
        existing.filter { it != wanted }.forEach { am.removeAccountExplicitly(it) }
        val visibility = TrustedConsumers.PINS.keys.associateWith { AccountManager.VISIBILITY_VISIBLE }
        if (existing.none { it == wanted }) {
            val data = Bundle().apply {
                putString(KEY_SERVER_URL, account.serverUrl)
                putString(KEY_USER_ID, userId)
                putString(KEY_DEVICE_ID, account.deviceId)
            }
            return runCatching { am.addAccountExplicitly(wanted, null, data, visibility) }.getOrDefault(false)
        }
        run {
            am.setUserData(wanted, KEY_SERVER_URL, account.serverUrl)
            am.setUserData(wanted, KEY_USER_ID, userId)
            am.setUserData(wanted, KEY_DEVICE_ID, account.deviceId)
            visibility.forEach { (pkg, v) -> am.setAccountVisibility(wanted, pkg, v) }
        }
        return true
    }

    fun remove(context: Context) { sync(context, null) }
}
