package org.kysecurity.authenticator.security

import android.content.Context
import android.content.SharedPreferences
import java.util.Base64
import javax.crypto.Cipher
import org.json.JSONObject

/** The VaultKek-wrapped plaintext: `{"totp": base64}`. Unknown fields from older builds are ignored. */
internal fun serializeWrappedKeys(totpKey: ByteArray): ByteArray =
    JSONObject().put("totp", Base64.getEncoder().encodeToString(totpKey)).toString().toByteArray(Charsets.UTF_8)

internal fun parseWrappedKeys(plain: ByteArray): ByteArray =
    Base64.getDecoder().decode(JSONObject(String(plain, Charsets.UTF_8)).getString("totp"))

/**
 * Owns the lock state and the TOTP vault key, wrapped by [VaultKek], an authentication-bound
 * Keystore key: unwrapping requires a cipher the framework has already authenticated.
 */
object AppLockManager {
    private const val PREFS_NAME = "app_lock"
    private const val KEY_PIN_HASH = "pin_hash"
    private const val KEY_PIN_SALT = "pin_salt"
    private const val KEY_KEK_WRAPPED_KEYS = "kek_wrapped_keys"
    private const val KEY_VAULT_SALT = "vault_salt"
    private const val KEY_WRAPPED_VAULT_KEY = "wrapped_vault_key"
    private const val KEY_PIN_ENABLED = "pin_enabled"
    private const val KEY_FAILED_ATTEMPTS = "failed_attempts"
    private const val KEY_RETRY_AFTER_EPOCH_SEC = "retry_after_epoch_sec"

    private const val LEGACY_BIOMETRIC_WRAPPED_VAULT_KEY = "biometric_wrapped_vault_key"

    // Retired with the password vault; removed so no wrapped key outlives it.
    private const val RETIRED_HAS_PASSWORD_VAULT_KEY = "has_password_vault_key"
    private const val RETIRED_PASSWORD_VAULT_SALT = "password_vault_salt"
    private const val RETIRED_WRAPPED_PASSWORD_VAULT_KEY = "wrapped_password_vault_key"
    private const val RETIRED_BIOMETRIC_WRAPPED_PASSWORD_VAULT_KEY = "biometric_wrapped_password_vault_key"

    @Volatile
    private var activeVaultKey: ByteArray? = null

    @Volatile
    private var isUnlocked: Boolean = false

    @Volatile
    var lockGeneration: Long = 0L
        private set

    val idleLock = IdleLock()

    fun isUnlocked(): Boolean = isUnlocked

    fun getVaultKey(): ByteArray? = if (isUnlocked) activeVaultKey else null

    @Synchronized
    fun lock() {
        lockGeneration++
        idleLock.reset()
        isUnlocked = false
        activeVaultKey?.fill(0)
        activeVaultKey = null
    }

    fun onWipe() {
        lock()
        VaultKek.delete()
    }

    private fun getPrefs(context: Context): SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun isPinEnabled(context: Context): Boolean =
        getPrefs(context).getBoolean(KEY_PIN_ENABLED, false)

    fun hasPinSet(context: Context): Boolean =
        getPrefs(context).getString(KEY_PIN_HASH, null) != null

    fun getFailureState(context: Context): PinFailureState {
        val prefs = getPrefs(context)
        return PinFailureState(
            failedAttempts = prefs.getInt(KEY_FAILED_ATTEMPTS, 0),
            retryAfterEpochSeconds = prefs.getLong(KEY_RETRY_AFTER_EPOCH_SEC, 0L),
        )
    }

    /** Written synchronously: an attempt must be durably counted before the caller learns the result. */
    private fun saveFailureState(context: Context, state: PinFailureState) {
        getPrefs(context).edit()
            .putInt(KEY_FAILED_ATTEMPTS, state.failedAttempts)
            .putLong(KEY_RETRY_AFTER_EPOCH_SEC, state.retryAfterEpochSeconds)
            .commit()
    }

    fun clearFailureState(context: Context) {
        saveFailureState(context, PinFailureState(0, 0L))
    }

    /**
     * Sets or changes the local PIN. Derives keys, wraps the vault key, and stores salt/hash.
     */
    @Synchronized
    fun setupPin(context: Context, pin: String) {
        val validation = PinPolicy.validate(pin)
        require(validation is PinPolicy.ValidationResult.Valid) {
            (validation as PinPolicy.ValidationResult.Error).message
        }
        check(isUnlocked) { "Unlock KyAuth before setting a PIN" }

        KeystoreCredentialPepper.ensureExists()
        KeystorePinPepper.ensureExists()

        val pinSalt = CredentialCipher.generateRandomSalt()
        val vaultSalt = CredentialCipher.generateRandomSalt()
        val pinHash = CredentialCipher.hashPinForStorage(pin, pinSalt)

        val vaultKey = checkNotNull(activeVaultKey) { "No vault key to protect with a PIN" }
        val wrapped = CredentialCipher.wrap(vaultKey, CredentialCipher.deriveKey(pin, vaultSalt))

        val editor = getPrefs(context).edit()
            .putString(KEY_PIN_HASH, pinHash)
            .putString(KEY_PIN_SALT, Base64.getEncoder().encodeToString(pinSalt))
            .putString(KEY_VAULT_SALT, Base64.getEncoder().encodeToString(vaultSalt))
            .putString(KEY_WRAPPED_VAULT_KEY, wrapped.serialize())
            .putBoolean(KEY_PIN_ENABLED, true)

        editor.commit()
        clearFailureState(context)
    }

    fun setPinEnabled(context: Context, enabled: Boolean) {
        getPrefs(context).edit().putBoolean(KEY_PIN_ENABLED, enabled).apply()
    }

    /**
     * Returns the cipher that must be handed to `BiometricPrompt.CryptoObject`, creating the
     * wrapping key on first use. Throws [VaultKek.NoSecureLockScreen] on a device that cannot bind
     * a key to user authentication — surfaced here, before the prompt, so the user is told why.
     */
    fun unlockCipher(): Cipher = VaultKek.unwrapCipher()

    /**
     * Unlocks with Biometric / Device Credential. [authenticatedCipher] must come from a
     * `BiometricPrompt.AuthenticationResult`; it may only be null on a device with no wrapped keys.
     */
    @Synchronized
    fun unlockWithBiometrics(context: Context, authenticatedCipher: Cipher?): Boolean {
        val key = when {
            getPrefs(context).getString(KEY_KEK_WRAPPED_KEYS, null) != null -> {
                val cipher = authenticatedCipher ?: return false
                unwrapKeys(context, cipher) ?: return false
            }
            hasLegacyWrapping(context) -> migrateLegacyWrapping(context) ?: return false
            else -> CredentialCipher.generateVaultKey()
        }
        adopt(context, key)
        clearFailureState(context)
        return true
    }

    /**
     * Verifies PIN and unlocks the vault. Enforces escalating delay and self-wipe after 5 failed
     * attempts. Synchronized so that concurrent attempts cannot share one failure count.
     */
    @Synchronized
    fun unlockWithPin(
        context: Context,
        pin: String,
        nowEpochSeconds: Long = System.currentTimeMillis() / 1000,
    ): Boolean {
        val state = getFailureState(context)
        if (!PinFailurePolicy.mayTry(state, nowEpochSeconds)) {
            return false
        }

        val prefs = getPrefs(context)
        val storedHash = prefs.getString(KEY_PIN_HASH, null) ?: return false
        val pinSaltB64 = prefs.getString(KEY_PIN_SALT, null) ?: return false
        val vaultSaltB64 = prefs.getString(KEY_VAULT_SALT, null) ?: return false
        val wrappedB64 = prefs.getString(KEY_WRAPPED_VAULT_KEY, null) ?: return false

        val pinSalt = Base64.getDecoder().decode(pinSaltB64)
        val candidateHash = CredentialCipher.hashPinForStorage(pin, pinSalt)

        if (candidateHash != storedHash) {
            val newState = PinFailurePolicy.registerFailure(state, nowEpochSeconds)
            saveFailureState(context, newState)

            if (PinFailurePolicy.mustWipe(newState)) {
                SecurityWipe.wipe(context)
            }
            return false
        }

        val vaultKey = runCatching {
            val wrapped = WrappedSecret.deserialize(wrappedB64) ?: return false
            CredentialCipher.unwrap(wrapped, CredentialCipher.deriveKey(pin, Base64.getDecoder().decode(vaultSaltB64)))
        }.getOrNull() ?: return false

        clearFailureState(context)
        adopt(context, vaultKey)
        return true
    }

    private fun adopt(context: Context, key: ByteArray) {
        activeVaultKey?.fill(0)
        activeVaultKey = key
        isUnlocked = true
        persistWrappedKeys(context)
    }

    private fun unwrapKeys(context: Context, authenticatedCipher: Cipher): ByteArray? {
        val blob = getPrefs(context).getString(KEY_KEK_WRAPPED_KEYS, null) ?: return null
        return runCatching {
            val plain = VaultKek.unwrap(authenticatedCipher, Base64.getDecoder().decode(blob))
            try { parseWrappedKeys(plain) } finally { plain.fill(0) }
        }.getOrNull()
    }

    private fun persistWrappedKeys(context: Context) {
        val totpKey = activeVaultKey ?: return
        val wrapped = VaultKek.wrap(serializeWrappedKeys(totpKey))
        getPrefs(context).edit()
            .putString(KEY_KEK_WRAPPED_KEYS, Base64.getEncoder().encodeToString(wrapped))
            .remove(LEGACY_BIOMETRIC_WRAPPED_VAULT_KEY)
            .remove(RETIRED_HAS_PASSWORD_VAULT_KEY)
            .remove(RETIRED_PASSWORD_VAULT_SALT)
            .remove(RETIRED_WRAPPED_PASSWORD_VAULT_KEY)
            .remove(RETIRED_BIOMETRIC_WRAPPED_PASSWORD_VAULT_KEY)
            .commit()
    }

    private fun hasLegacyWrapping(context: Context): Boolean =
        getPrefs(context).getString(LEGACY_BIOMETRIC_WRAPPED_VAULT_KEY, null) != null

    /**
     * One-shot upgrade from the pre-[VaultKek] wrapping, which any in-process code could undo.
     * Only reachable after a successful authentication. Delete once no v0.1 installs remain.
     */
    private fun migrateLegacyWrapping(context: Context): ByteArray? {
        val prefs = getPrefs(context)
        return runCatching {
            val blob = prefs.getString(LEGACY_BIOMETRIC_WRAPPED_VAULT_KEY, null) ?: return null
            val salt = Base64.getDecoder().decode(prefs.getString(KEY_VAULT_SALT, null) ?: return null)
            val wrapped = WrappedSecret.deserialize(blob) ?: return null
            CredentialCipher.unwrap(wrapped, CredentialCipher.deriveLegacyWrapKey(salt))
        }.getOrNull()
    }
}
