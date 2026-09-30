package org.kysecurity.authenticator.signon

import android.accounts.AccountManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kysecurity.authenticator.pairing.PairedAccount

class SignOnRequestTest {
    private val caller = TrustedCaller("org.kysecurity.mail", "KyPost")
    private val relay = "https://Mail.Example.com:443/relay"
    private val paired = PairedAccount("https://id.example.com", "dev-1", "Pixel", "alice", "u1", canSignOn = true)

    @Test
    fun proceeds_forPinnedCallerValidTypeAndSignOnDevice() {
        val r = decideSignOn(caller, "kypost", relay, paired)
        assertTrue(r is SignOnRequest.Proceed)
        assertEquals("kypost", (r as SignOnRequest.Proceed).clientId)
        assertEquals("https://mail.example.com", r.origin)
    }

    @Test
    fun refuses_missingOrInsecureOrigin() {
        for (bad in listOf(null, "", "  ", "http://mail.example.com", "https://u@mail.example.com")) {
            val r = decideSignOn(caller, "kypost", bad, paired) as SignOnRequest.Refuse
            assertEquals("origin $bad", AccountManager.ERROR_CODE_BAD_ARGUMENTS, r.code)
        }
    }

    @Test
    fun refusal_order_callerThenClientIdThenOriginThenPairing() {
        assertEquals(AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION, (decideSignOn(null, "bad id!", "http://x", null) as SignOnRequest.Refuse).code)
        assertEquals("Invalid client id", (decideSignOn(caller, "bad id!", "http://x", null) as SignOnRequest.Refuse).message)
        assertEquals(AccountManager.ERROR_CODE_BAD_ARGUMENTS, (decideSignOn(caller, "kypost", "http://x", null) as SignOnRequest.Refuse).code)
    }

    @Test
    fun refuses_unpinnedCaller() {
        val r = decideSignOn(null, "kypost", relay, paired) as SignOnRequest.Refuse
        assertEquals(AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION, r.code)
    }

    @Test
    fun refuses_badClientId() {
        val r = decideSignOn(caller, "bad id!", relay, paired) as SignOnRequest.Refuse
        assertEquals(AccountManager.ERROR_CODE_BAD_ARGUMENTS, r.code)
    }

    @Test
    fun refuses_whenNotPairedOrSignOnOff() {
        assertEquals(AccountManager.ERROR_CODE_BAD_REQUEST, (decideSignOn(caller, "kypost", relay, null) as SignOnRequest.Refuse).code)
        assertEquals(AccountManager.ERROR_CODE_BAD_REQUEST, (decideSignOn(caller, "kypost", relay, paired.copy(canSignOn = false)) as SignOnRequest.Refuse).code)
        assertEquals(AccountManager.ERROR_CODE_BAD_REQUEST, (decideSignOn(caller, "kypost", relay, paired.copy(userId = null)) as SignOnRequest.Refuse).code)
    }

    @Test
    fun cleanup_onlyWhenReadSucceededAndBadRequest() {
        val bad = SignOnRequest.Refuse(AccountManager.ERROR_CODE_BAD_REQUEST, "x")
        assertTrue(cleanupAfterRefusal(true, bad))
        assertTrue(!cleanupAfterRefusal(false, bad))
        assertTrue(!cleanupAfterRefusal(true, SignOnRequest.Refuse(AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION, "x")))
        assertTrue(!cleanupAfterRefusal(true, SignOnRequest.Proceed(caller, "kypost", "https://mail.example.com", paired)))
    }
}
