package org.kysecurity.authenticator.totp

import java.io.File
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import org.kysecurity.authenticator.security.writeAtomically

/** The vault file exists but cannot be read. Callers must not save over it. */
class TotpVaultException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * TOTP entries in one file: version (0x01) || 12-byte nonce || AES-256-GCM ciphertext and 16-byte
 * tag over a JSON array. AAD is UTF-8 "kyauth-totp-v1" || version.
 */
object TotpVault {
    private const val VERSION: Byte = 1
    private const val NONCE_BYTES = 12
    private const val TAG_BITS = 128
    private val AAD = "kyauth-totp-v1".toByteArray(Charsets.UTF_8) + VERSION
    private val random = SecureRandom()
    private const val JSON_WHITESPACE = " \t\n\r"

    /** A missing file is an empty vault; anything else unreadable throws [TotpVaultException]. */
    @Synchronized
    fun load(file: File, key: ByteArray): List<TotpEntry> {
        if (!file.exists()) return emptyList()
        val bytes = try {
            file.readBytes()
        } catch (e: IOException) {
            throw TotpVaultException("TOTP vault could not be read", e)
        }
        if (bytes.size < 1 + NONCE_BYTES + TAG_BITS / 8) throw TotpVaultException("TOTP vault is truncated")
        if (bytes[0] != VERSION) throw TotpVaultException("Unsupported TOTP vault version ${bytes[0]}")
        val plain = try {
            cipher(Cipher.DECRYPT_MODE, key, bytes.copyOfRange(1, 1 + NONCE_BYTES))
                .doFinal(bytes, 1 + NONCE_BYTES, bytes.size - 1 - NONCE_BYTES)
        } catch (e: GeneralSecurityException) {
            throw TotpVaultException("TOTP vault could not be decrypted", e)
        }
        try {
            // JSONArray(String) stops after the array, and Android's nextClean() skips comments, so
            // read the rest raw: the whole document must be one array plus JSON whitespace.
            val tokens = JSONTokener(String(plain, Charsets.UTF_8))
            val array = tokens.nextValue() as JSONArray
            while (tokens.more()) {
                if (tokens.next() !in JSON_WHITESPACE) throw TotpVaultException("TOTP vault has trailing content")
            }
            return List(array.length()) { fromJson(array.getJSONObject(it)) }
        } catch (e: TotpVaultException) {
            throw e
        } catch (e: Exception) {
            throw TotpVaultException("TOTP vault content is invalid", e)
        } finally {
            plain.fill(0)
        }
    }

    @Synchronized
    fun save(file: File, key: ByteArray, entries: List<TotpEntry>) {
        val plain = JSONArray(entries.map(::toJson)).toString().toByteArray(Charsets.UTF_8)
        try {
            val nonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
            writeAtomically(file, byteArrayOf(VERSION) + nonce + cipher(Cipher.ENCRYPT_MODE, key, nonce).doFinal(plain))
        } finally {
            plain.fill(0)
        }
    }

    private fun cipher(mode: Int, key: ByteArray, nonce: ByteArray): Cipher {
        require(key.size == 32) { "TOTP vault key must be 256 bits" }
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
            updateAAD(AAD)
        }
    }

    private fun toJson(e: TotpEntry) = JSONObject()
        .put("id", e.id)
        .put("title", e.title)
        .put("secretBase32", e.secretBase32)
        .put("digits", e.digits)
        .put("periodSeconds", e.periodSeconds)
        .put("algorithm", e.algorithm.name)
        .put("issuer", e.issuer)
        .put("url", e.url)
        .put("notes", e.notes)

    private fun fromJson(o: JSONObject) = TotpEntry(
        id = o.getString("id"),
        title = o.getString("title"),
        secretBase32 = o.getString("secretBase32"),
        digits = o.getInt("digits"),
        periodSeconds = o.getLong("periodSeconds"),
        algorithm = TotpEntry.Algorithm.valueOf(o.getString("algorithm")),
        issuer = o.stringOrNull("issuer"),
        url = o.stringOrNull("url"),
        notes = o.stringOrNull("notes"),
    )

    private fun JSONObject.stringOrNull(name: String) = if (has(name)) getString(name) else null
}
