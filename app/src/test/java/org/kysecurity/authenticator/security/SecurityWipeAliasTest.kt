package org.kysecurity.authenticator.security

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
            // Both halves of the alternating KyIdentity passkey pair; a key left behind here is a
            // live authentication factor surviving a wipe.
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
