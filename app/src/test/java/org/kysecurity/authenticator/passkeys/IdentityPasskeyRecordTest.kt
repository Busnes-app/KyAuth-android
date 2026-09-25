package org.kysecurity.authenticator.passkeys

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class IdentityPasskeyRecordTest {

    private fun record() = IdentityPasskeyRecord(
        rpId = "identity.example.com",
        username = "yoshi",
        userHandle = byteArrayOf(1, 2, 3),
        credentialId = byteArrayOf(9, 8, 7, 6),
        signCount = 4,
        alias = "kyauth_identity_passkey_a",
        strongBoxBacked = true,
    )

    @Test
    fun `round trips through json`() {
        assertEquals(record(), IdentityPasskeyRecord.fromJson(record().toJson()))
    }

    @Test
    fun `rejects malformed or absent json instead of throwing`() {
        assertNull(IdentityPasskeyRecord.fromJson(null))
        assertNull(IdentityPasskeyRecord.fromJson(""))
        assertNull(IdentityPasskeyRecord.fromJson("not json"))
        assertNull(IdentityPasskeyRecord.fromJson("""{"rpId":"identity.example.com"}"""))
    }

    @Test
    fun `an empty user handle survives the round trip`() {
        val empty = record().copy(userHandle = ByteArray(0))
        assertEquals(empty, IdentityPasskeyRecord.fromJson(empty.toJson()))
    }
}
