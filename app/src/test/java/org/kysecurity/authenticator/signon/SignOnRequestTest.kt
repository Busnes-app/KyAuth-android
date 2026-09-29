package org.kysecurity.authenticator.signon

import android.accounts.AccountManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kysecurity.authenticator.pairing.PairedAccount

class SignOnRequestTest {
    private val caller = TrustedCaller("org.kysecurity.mail", "KyPost")
    private val paired = PairedAccount("https://id.example.com", "dev-1", "Pixel", "alice", "u1", canSignOn = true)

    @Test
    fun proceeds_forPinnedCallerValidTypeAndSignOnDevice() {
        val r = decideSignOn(caller, "kypost", paired)
        assertTrue(r is SignOnRequest.Proceed)
        assertEquals("kypost", (r as SignOnRequest.Proceed).clientId)
    }

    @Test
    fun refuses_unpinnedCaller() {
        val r = decideSignOn(null, "kypost", paired) as SignOnRequest.Refuse
        assertEquals(AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION, r.code)
    }

    @Test
    fun refuses_badClientId() {
        val r = decideSignOn(caller, "bad id!", paired) as SignOnRequest.Refuse
        assertEquals(AccountManager.ERROR_CODE_BAD_ARGUMENTS, r.code)
    }

    @Test
    fun refuses_whenNotPairedOrSignOnOff() {
        assertEquals(AccountManager.ERROR_CODE_BAD_REQUEST, (decideSignOn(caller, "kypost", null) as SignOnRequest.Refuse).code)
        assertEquals(AccountManager.ERROR_CODE_BAD_REQUEST, (decideSignOn(caller, "kypost", paired.copy(canSignOn = false)) as SignOnRequest.Refuse).code)
        assertEquals(AccountManager.ERROR_CODE_BAD_REQUEST, (decideSignOn(caller, "kypost", paired.copy(userId = null)) as SignOnRequest.Refuse).code)
    }

    @Test
    fun cleanup_onlyWhenReadSucceededAndBadRequest() {
        val bad = SignOnRequest.Refuse(AccountManager.ERROR_CODE_BAD_REQUEST, "x")
        assertTrue(cleanupAfterRefusal(true, bad))
        assertTrue(!cleanupAfterRefusal(false, bad))
        assertTrue(!cleanupAfterRefusal(true, SignOnRequest.Refuse(AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION, "x")))
        assertTrue(!cleanupAfterRefusal(true, SignOnRequest.Proceed(caller, "kypost", paired)))
    }
}
