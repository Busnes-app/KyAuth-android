package org.kysecurity.authenticator.signon

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kysecurity.authenticator.pairing.PairingEndpoint

class TokenClientTest {
    private val client = TokenClient()

    @Test
    fun formBody_isJwtBearerGrant() {
        val body = client.formBody("kypost", "h.c.s")
        assertEquals("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=h.c.s&client_id=kypost", body)
    }

    @Test
    fun parse_success() {
        val r = client.parse(200, """{"access_token":"a","token_type":"Bearer","expires_in":900,"id_token":"eyJ.x.y"}""") as TokenResult.Success
        assertEquals("eyJ.x.y", r.idToken)
        assertEquals("Success(redacted)", r.toString())
    }

    @Test
    fun parse_missingIdToken() {
        val r = client.parse(200, """{"access_token":"a"}""")
        assertTrue(r is TokenResult.Failure)
    }

    @Test
    fun parse_signOnDisabled() {
        val r = client.parse(400, """{"error":"invalid_grant","error_description":"device_signon_disabled"}""") as TokenResult.Failure
        assertTrue(r.userMessage.contains("KyIdentity devices page"))
    }

    @Test
    fun parse_signOnNotPermitted() {
        val r = client.parse(400, """{"error":"invalid_grant","error_description":"signon_not_permitted"}""") as TokenResult.Failure
        assertEquals("This account cannot sign in to apps from this phone right now. Use web sign-in.", r.userMessage)
    }

    @Test
    fun parse_unknownDescriptionIsGeneric() {
        val r = client.parse(400, """{"error":"invalid_grant","error_description":"something_new"}""") as TokenResult.Failure
        assertEquals("KyIdentity refused the sign-in (400).", r.userMessage)
    }

    @Test
    fun parse_otherErrorsAreGeneric() {
        val r = client.parse(400, """{"error":"invalid_grant","error_description":"The device assertion is invalid"}""") as TokenResult.Failure
        assertTrue(!r.userMessage.contains("turned off"))
        val rl = client.parse(429, "") as TokenResult.Failure
        assertTrue(rl.userMessage.contains("Try again"))
    }

    @Test
    fun tokenUrl_keepsBasePathAndRejectsPlainHttp() {
        assertEquals("https://id.example.com/idp/oauth/token", PairingEndpoint.tokenUrl("https://id.example.com/idp/").toString())
        assertTrue(runCatching { PairingEndpoint.tokenUrl("http://id.example.com") }.isFailure)
    }
}
