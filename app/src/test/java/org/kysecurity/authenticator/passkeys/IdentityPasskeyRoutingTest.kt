package org.kysecurity.authenticator.passkeys

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IdentityPasskeyRoutingTest {

    @Test
    fun `derives the rp id from the paired server url`() {
        assertEquals("identity.example.com", IdentityPasskey.identityRpId("https://identity.example.com"))
        assertEquals("identity.example.com", IdentityPasskey.identityRpId("https://identity.example.com:8443/pair"))
    }

    @Test
    fun `unpaired device has no identity rp id`() {
        assertNull(IdentityPasskey.identityRpId(null))
        assertNull(IdentityPasskey.identityRpId(""))
    }

    @Test
    fun `matches only the paired host exactly`() {
        val server = "https://identity.example.com"
        assertTrue(IdentityPasskey.isIdentityRpId("identity.example.com", server))
        // Subdomain and parent must not match: WebAuthn scopes a credential to exactly one RP ID.
        assertFalse(IdentityPasskey.isIdentityRpId("login.identity.example.com", server))
        assertFalse(IdentityPasskey.isIdentityRpId("example.com", server))
        assertFalse(IdentityPasskey.isIdentityRpId("identity.example.com.evil.test", server))
    }

    @Test
    fun `an unpaired device routes nothing to the local store`() {
        assertFalse(IdentityPasskey.isIdentityRpId("identity.example.com", null))
    }

    @Test
    fun `keeps a www host instead of widening to its parent`() {
        // Exact match only: a leading "www." is a different RP ID.
        assertEquals("www.identity.example.com", IdentityPasskey.identityRpId("https://www.identity.example.com"))
    }

    @Test
    fun `a www pairing url does not match its parent domain`() {
        val server = "https://www.identity.example.com"
        assertTrue(IdentityPasskey.isIdentityRpId("www.identity.example.com", server))
        assertFalse(IdentityPasskey.isIdentityRpId("identity.example.com", server))
        assertFalse(IdentityPasskey.isIdentityRpId("blog.identity.example.com", server))
    }

    @Test
    fun createIsOfferedOnlyForTheExactPairedHost() {
        assertTrue(identityCreateTarget("id.example.com", "https://id.example.com"))
        assertFalse(identityCreateTarget("example.com", "https://id.example.com"))
        assertFalse(identityCreateTarget("www.id.example.com", "https://id.example.com"))
        assertFalse(identityCreateTarget("evil.test", "https://id.example.com"))
        assertFalse(identityCreateTarget("id.example.com", null))
    }
}
