package org.kysecurity.authenticator.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The wipe sweeps AndroidKeyStore by alias prefix. A KyAuth key the sweep does not match survives a
 * local wipe, so every alias the app creates is pinned here by its literal value.
 */
class SecurityWipeAliasTest {

    @Test
    fun `matches every alias KyAuth creates`() {
        val aliases = listOf(
            "kyauth_vault_kek",
            "kyauth_credential_pepper",
            "kyauth_pin_pepper",
            "kyidentity-device-signing-v1",
            "kysignon-device-signing-v1",
            "kyauth_fcm_push_keys", // PushKeyWrap.ALIAS: the sealed FCM push keys
            // The removed KyIdentity passkey: a key left behind is a live factor surviving a wipe.
            "kyauth_identity_passkey_a",
            "kyauth_identity_passkey_b",
            "kyauth_signon_passkey_a",
            "kyauth_signon_passkey_b",
        )
        for (alias in aliases) {
            assertTrue("wipe would leave $alias behind", SecurityWipe.isAppAlias(alias))
        }
    }

    @Test
    fun `wipe also covers everything the removed-passkey cleanup deletes`() {
        assertEquals(
            listOf("kyauth_identity_passkey_a", "kyauth_identity_passkey_b", "kyauth_signon_passkey_a", "kyauth_signon_passkey_b"),
            RemovedPasskey.ALIASES,
        )
        assertEquals(listOf("identity_passkey_store", "identity_passkey"), RemovedPasskey.PREFS)
        assertTrue(SecurityWipe.PREFS_FILES.containsAll(RemovedPasskey.PREFS))
    }

    @Test
    fun `prefix sweep does not match the androidx master key`() {
        // The prefix sweep does not match it; SecurityWipe deletes it by name.
        assertFalse(SecurityWipe.isAppAlias("_androidx_security_master_key_"))
    }

    @Test
    fun `ignores keys belonging to other software`() {
        assertFalse(SecurityWipe.isAppAlias("bitwarden_key"))
        assertFalse(SecurityWipe.isAppAlias("com.example.kyauth_lookalike"))
    }
}
