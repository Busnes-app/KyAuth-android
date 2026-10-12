package org.kysecurity.authenticator.totp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class TotpVaultTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    private val key = ByteArray(32) { (it + 1).toByte() }
    private val file by lazy { File(tempFolder.root, "totp_vault.bin") }

    private val entries = listOf(
        TotpEntry(
            title = "Google (test@gmail.com)",
            secretBase32 = "JBSWY3DPEHPK3PXP",
            issuer = "Google",
            url = "https://accounts.google.com",
            notes = "Personal account notes",
        ),
        TotpEntry(
            title = "GitHub (user)",
            secretBase32 = "NBSWY3DPEHPK3PXP",
            digits = 8,
            periodSeconds = 60,
            algorithm = TotpEntry.Algorithm.SHA512,
        ),
    )

    private fun assertUnreadable() {
        assertThrows(TotpVaultException::class.java) { TotpVault.load(file, key) }
    }

    @Test fun `round trips every field`() {
        TotpVault.save(file, key, entries)
        assertEquals(entries, TotpVault.load(file, key))
        assertEquals(1.toByte(), file.readBytes()[0])
    }

    @Test fun `replaces the file atomically and leaves no temp`() {
        TotpVault.save(file, key, entries)
        TotpVault.save(file, key, entries.take(1))
        assertEquals(entries.take(1), TotpVault.load(file, key))
        assertEquals(listOf(file.name), tempFolder.root.list()!!.toList())
    }

    @Test fun `uses a fresh nonce on every save`() {
        TotpVault.save(file, key, entries)
        val first = file.readBytes()
        TotpVault.save(file, key, entries)
        val second = file.readBytes()
        assertFalse(first.copyOfRange(1, 13).contentEquals(second.copyOfRange(1, 13)))
        assertFalse(first.contentEquals(second))
    }

    @Test fun `missing file is an empty vault`() {
        assertEquals(emptyList<TotpEntry>(), TotpVault.load(file, key))
    }

    @Test fun `wrong key fails`() {
        TotpVault.save(file, key, entries)
        assertThrows(TotpVaultException::class.java) { TotpVault.load(file, ByteArray(32)) }
    }

    @Test fun `flipped ciphertext byte fails`() {
        TotpVault.save(file, key, entries)
        val bytes = file.readBytes()
        bytes[20] = (bytes[20].toInt() xor 1).toByte()
        file.writeBytes(bytes)
        assertUnreadable()
    }

    @Test fun `wrong version byte fails`() {
        TotpVault.save(file, key, entries)
        file.writeBytes(file.readBytes().also { it[0] = 2 })
        assertUnreadable()
    }

    @Test fun `truncated file fails`() {
        TotpVault.save(file, key, entries)
        val bytes = file.readBytes()
        file.writeBytes(bytes.copyOf(bytes.size - 1))
        assertUnreadable()
        file.writeBytes(bytes.copyOf(20))
        assertUnreadable()
        file.writeBytes(ByteArray(0))
        assertUnreadable()
    }

    @Test fun `ciphertext under another AAD fails`() {
        val nonce = ByteArray(12) { 7 }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            updateAAD("kyauth-totp-v2".toByteArray() + 1.toByte())
        }
        file.writeBytes(byteArrayOf(1) + nonce + cipher.doFinal("[]".toByteArray()))
        assertUnreadable()
    }

    /** Writes [plain] as a correctly authenticated vault file. */
    private fun writeAuthentic(plain: String) {
        val nonce = ByteArray(12) { 7 }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            updateAAD("kyauth-totp-v1".toByteArray() + 1.toByte())
        }
        file.writeBytes(byteArrayOf(1) + nonce + cipher.doFinal(plain.toByteArray()))
    }

    @Test fun `a valid tag over invalid JSON fails`() {
        writeAuthentic("[{}]")
        assertUnreadable()
    }

    @Test fun `a valid tag over trailing content fails and leaves the file`() {
        writeAuthentic("[] trailing")
        val before = file.readBytes()
        assertUnreadable()
        assertArrayEquals(before, file.readBytes())
        writeAuthentic("[]  \n")
        assertEquals(emptyList<TotpEntry>(), TotpVault.load(file, key))
    }

    @Test fun `an unreadable path is a vault error, not an IOException`() {
        file.mkdirs()
        assertUnreadable()
    }

    @Test fun `failed load leaves the file untouched`() {
        TotpVault.save(file, key, entries)
        val before = file.readBytes()
        assertThrows(TotpVaultException::class.java) { TotpVault.load(file, ByteArray(32)) }
        assertArrayEquals(before, file.readBytes())
    }

    @Test fun `deletes the legacy KDBX vault and its temp files`() {
        val legacy = listOf("totp_vault.kdbx", ".totp_vault.kdbx.tmp", ".totp_vault.kdbx123.tmp")
            .map { File(tempFolder.root, it).apply { writeText("x") } }
        val unrelated = File(tempFolder.root, "other.kdbx").apply { writeText("x") }
        TotpVault.load(file, key)
        TotpVault.load(file, key)
        assertTrue(legacy.none { it.exists() })
        assertTrue(unrelated.exists())
    }
}
