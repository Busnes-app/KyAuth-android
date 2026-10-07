package org.kysecurity.authenticator.passkeys

import android.content.Context

/**
 * Persists the non-secret half of the KyIdentity passkey. The private key is non-exportable and
 * never passes through here — only rpId, credential id, user handle, sign count, the Keystore
 * alias and which hardware backed it.
 *
 * Modelled on [org.kysecurity.authenticator.pairing.PairingStore]: plain app-private prefs, no
 * new crypto and deliberately not a third KDBX vault.
 */
class IdentityPasskeyStore(context: Context) {

    private val preferences = context.getSharedPreferences("identity_passkey_store", Context.MODE_PRIVATE)

    fun record(): IdentityPasskeyRecord? =
        IdentityPasskeyRecord.fromJson(preferences.getString(KEY_RECORD, null))

    fun save(record: IdentityPasskeyRecord) {
        preferences.edit().putString(KEY_RECORD, record.toJson()).apply()
    }

    fun clear() {
        preferences.edit().remove(KEY_RECORD).apply()
    }

    private companion object {
        const val KEY_RECORD = "record"
    }
}
