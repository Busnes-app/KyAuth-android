package org.kysecurity.authenticator.pairing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream

class ServerHttpTest {
    @Test
    fun readsABodyUpToTheCap() {
        val body = "x".repeat(ServerHttp.MAX_BODY_BYTES)
        assertEquals(body, ServerHttp.readBounded(ByteArrayInputStream(body.toByteArray())))
    }

    @Test
    fun refusesABodyPastTheCap() {
        val body = ByteArray(ServerHttp.MAX_BODY_BYTES + 1)
        assertThrows(IOException::class.java) { ServerHttp.readBounded(ByteArrayInputStream(body)) }
    }

    @Test
    fun refusesAServerThatDripsPastTheDeadline() {
        var now = 0L
        val drip = object : InputStream() {
            override fun read(): Int = 'x'.code.also { now += 1_000 }
            override fun read(b: ByteArray, off: Int, len: Int): Int { b[off] = read().toByte(); return 1 }
        }
        assertThrows(IOException::class.java) { ServerHttp.readBounded(drip, deadlineMs = 30_000, nowMs = { now }) }
    }

    @Test
    fun errorPrefersTheServerDescription() {
        assertEquals("nope", ServerHttp.Response(400, """{"error":"bad","error_description":"nope"}""").error("Failed"))
        assertEquals("bad", ServerHttp.Response(400, """{"error":"bad"}""").error("Failed"))
        assertEquals("Failed (502)", ServerHttp.Response(502, "<html>").error("Failed"))
    }
}
