package org.kysecurity.authenticator.pairing

import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URI
import javax.net.ssl.HttpsURLConnection

/**
 * One blocking request to KyIdentity. No redirects, and the body is capped in size and total time:
 * the server comes from a QR code, so a hostile one must not hang the app or exhaust its memory.
 */
object ServerHttp {
    internal const val MAX_BODY_BYTES = 64 * 1024
    private const val TIMEOUT_MS = 10_000
    private const val DEADLINE_MS = 30_000L

    class Response(val status: Int, val body: String) {
        val ok get() = status in 200..299

        /** KyIdentity's `error_description` or `error`, else [fallback] with the status. */
        fun error(fallback: String): String {
            val json = runCatching { JSONObject(body) }.getOrNull()
            return json?.optString("error_description")?.takeIf { it.isNotBlank() }
                ?: json?.optString("error")?.takeIf { it.isNotBlank() }
                ?: "$fallback ($status)"
        }
    }

    fun send(url: URI, method: String, contentType: String, body: String): Response {
        val connection = (url.toURL().openConnection() as HttpURLConnection).apply {
            // PairingEndpoint requires HTTPS in release; HTTP is debug-loopback only.
            if (this is HttpsURLConnection) {
                sslSocketFactory = try { ServerTls.socketFactory } catch (e: Exception) {
                    throw IOException("Secure TLS is unavailable on this device", e)
                }
            }
            requestMethod = method
            connectTimeout = TIMEOUT_MS
            readTimeout = TIMEOUT_MS
            doOutput = true
            instanceFollowRedirects = false
            setRequestProperty("Content-Type", contentType)
            setRequestProperty("Accept", "application/json")
        }
        try {
            connection.outputStream.bufferedWriter(Charsets.UTF_8).use { it.write(body) }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            return Response(status, stream?.use { readBounded(it) }.orEmpty())
        } finally {
            connection.disconnect()
        }
    }

    internal fun readBounded(
        input: InputStream,
        limit: Int = MAX_BODY_BYTES,
        deadlineMs: Long = DEADLINE_MS,
        nowMs: () -> Long = { System.nanoTime() / 1_000_000 },
    ): String {
        val end = nowMs() + deadlineMs
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(8 * 1024)
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            out.write(buffer, 0, read)
            if (out.size() > limit) throw IOException("The server's response is too large")
            if (nowMs() > end) throw IOException("The server took too long to respond")
        }
        return out.toString(Charsets.UTF_8.name())
    }
}
