package org.kysecurity.authenticator.signon

import android.accounts.AccountManager
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kysecurity.authenticator.pairing.PairedAccount
import java.util.Base64

class SignOnRequestTest {
    private val caller = TrustedCaller("org.kysecurity.mail", "KyPost")
    private val thumb = "Wnp4zKSg9CDZvGK7Zpw8J1njn3I9OuENy-DwgVoH7NQ"
    private val relay = "https://Mail.Example.com:443/relay"
    private val paired = PairedAccount("https://id.example.com", "dev-1", "Pixel", "alice", "u1", canSignOn = true)

    @Test
    fun proceeds_forPinnedCallerValidTypeAndSignOnDevice() {
        val r = decideSignOn(caller, "kypost", relay, null, paired)
        assertTrue(r is SignOnRequest.Proceed)
        assertEquals("kypost", (r as SignOnRequest.Proceed).clientId)
        assertEquals("https://mail.example.com", r.origin)
    }

    @Test
    fun refuses_missingOrInsecureOrigin() {
        for (bad in listOf(null, "", "  ", "http://mail.example.com", "https://u@mail.example.com")) {
            val r = decideSignOn(caller, "kypost", bad, null, paired) as SignOnRequest.Refuse
            assertEquals("origin $bad", AccountManager.ERROR_CODE_BAD_ARGUMENTS, r.code)
        }
    }

    @Test
    fun refusal_order_callerThenClientIdThenOriginThenPairing() {
        assertEquals(AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION, (decideSignOn(null, "bad id!", "http://x", "bad", null) as SignOnRequest.Refuse).code)
        assertEquals("Invalid client id", (decideSignOn(caller, "bad id!", "http://x", "bad", null) as SignOnRequest.Refuse).message)
        assertEquals(AccountManager.ERROR_CODE_BAD_ARGUMENTS, (decideSignOn(caller, "kypost", "http://x", "bad", null) as SignOnRequest.Refuse).code)
    }

    @Test
    fun refusal_cnfBeforePairing() {
        val r = decideSignOn(caller, "kypost", relay, "bad", null) as SignOnRequest.Refuse
        assertEquals(AccountManager.ERROR_CODE_BAD_ARGUMENTS, r.code)
        assertEquals("Invalid key binding", r.message)
    }

    @Test
    fun cnf_absentAllowed_validCarried() {
        assertNull((decideSignOn(caller, "kypost", relay, null, paired) as SignOnRequest.Proceed).cnf)
        assertEquals(thumb, (decideSignOn(caller, "kypost", relay, thumb, paired) as SignOnRequest.Proceed).cnf)
    }

    @Test
    fun cnf_malformedRefusedBeforePrompt() {
        val bad = listOf(
            "", thumb.dropLast(1), thumb + "A", thumb.dropLast(1) + "+", thumb.dropLast(1) + "/",
            thumb.dropLast(1) + "=", thumb.dropLast(2) + "==", " " + thumb.drop(1), thumb.dropLast(1) + "\n",
        )
        for (cnf in bad) {
            val r = decideSignOn(caller, "kypost", relay, cnf, paired) as SignOnRequest.Refuse
            assertEquals("cnf \"$cnf\"", AccountManager.ERROR_CODE_BAD_ARGUMENTS, r.code)
        }
    }

    @Test
    fun cnf_reachesTheAssertion() {
        // The path SignOnActivity takes: decision -> nonce handoff -> signingInput.
        val decided = decideSignOn(caller, "kypost", relay, thumb, paired) as SignOnRequest.Proceed
        val handed = PendingSignOn.take(PendingSignOn.issue(SignOnHandoff(decided, null)))!!.request
        val input = DeviceAssertion.signingInput("dev-1", "u1", paired.serverUrl, handed.clientId, handed.origin, 1000, "j", cnf = handed.cnf)
        val claims = JSONObject(String(Base64.getUrlDecoder().decode(input.split(".")[1])))
        assertEquals(thumb, claims.getJSONObject("cnf").getString("spki#S256"))
    }

    @Test
    fun refuses_unpinnedCaller() {
        val r = decideSignOn(null, "kypost", relay, null, paired) as SignOnRequest.Refuse
        assertEquals(AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION, r.code)
    }

    @Test
    fun refuses_badClientId() {
        val r = decideSignOn(caller, "bad id!", relay, null, paired) as SignOnRequest.Refuse
        assertEquals(AccountManager.ERROR_CODE_BAD_ARGUMENTS, r.code)
    }

    @Test
    fun refuses_whenNotPairedOrSignOnOff() {
        assertEquals(AccountManager.ERROR_CODE_BAD_REQUEST, (decideSignOn(caller, "kypost", relay, null, null) as SignOnRequest.Refuse).code)
        assertEquals(AccountManager.ERROR_CODE_BAD_REQUEST, (decideSignOn(caller, "kypost", relay, null, paired.copy(canSignOn = false)) as SignOnRequest.Refuse).code)
        assertEquals(AccountManager.ERROR_CODE_BAD_REQUEST, (decideSignOn(caller, "kypost", relay, null, paired.copy(userId = null)) as SignOnRequest.Refuse).code)
    }

    @Test
    fun cleanup_onlyWhenReadSucceededAndBadRequest() {
        val bad = SignOnRequest.Refuse(AccountManager.ERROR_CODE_BAD_REQUEST, "x")
        assertTrue(cleanupAfterRefusal(true, bad))
        assertTrue(!cleanupAfterRefusal(false, bad))
        assertTrue(!cleanupAfterRefusal(true, SignOnRequest.Refuse(AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION, "x")))
        assertTrue(!cleanupAfterRefusal(true, SignOnRequest.Proceed(caller, "kypost", "https://mail.example.com", null, paired)))
    }
}
