package org.kysecurity.authenticator.pairing

import android.net.http.X509TrustManagerExtensions
import android.util.Base64
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.URI
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedTrustManager

/** Real Android trust, with explicitly selected public loopback fixture anchors. */
@RunWith(AndroidJUnit4::class)
class ServerHttpTLSDeviceTest {
    private var controlPort = 0
    private val body = """{"probe":"public-fixture"}"""

    @Before fun requireFixtures() {
        val argument = InstrumentationRegistry.getArguments().getString("tlsFixtureControl")
        assumeTrue("Use scripts/test-android.sh for the native TLS proof", argument != null)
        controlPort = requireNotNull(argument).toInt()
        require(controlPort in 1..65535)
    }

    private fun control(path: String): JSONObject {
        val connection = URI("http://127.0.0.1:$controlPort/$path").toURL().openConnection() as HttpURLConnection
        return try {
            connection.connectTimeout = 5_000
            connection.readTimeout = 5_000
            JSONObject(connection.inputStream.bufferedReader().use { it.readText() })
        } finally { connection.disconnect() }
    }

    private fun certificate(encoded: String): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(
            ByteArrayInputStream(Base64.decode(encoded, Base64.DEFAULT)),
        ) as X509Certificate

    private fun certificates(spec: JSONObject): Array<X509Certificate> {
        val chain = spec.getJSONArray("chain")
        return Array(chain.length()) { certificate(chain.getString(it)) }
    }

    private fun uri(spec: JSONObject): URI {
        val host = spec.optString("host", "127.0.0.1")
        require(host == "127.0.0.1" || host.endsWith("kyauth-tls-test.invalid"))
        val port = spec.getInt("port")
        require(port in 1..65535)
        return URI("https://$host:$port/probe")
    }

    // Only reserved fixture names use this owned CONNECT tunnel. Other SDK traffic
    // retains its original proxy selection, and the selector is restored afterwards.
    private fun <T> withFixtureProxy(block: () -> T): T {
        val original = ProxySelector.getDefault()
        ProxySelector.setDefault(object : ProxySelector() {
            override fun select(uri: URI): List<Proxy> =
                if (uri.host?.endsWith("kyauth-tls-test.invalid") == true) {
                    listOf(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", controlPort)))
                } else original?.select(uri) ?: listOf(Proxy.NO_PROXY)
            override fun connectFailed(uri: URI, address: SocketAddress, error: IOException) = Unit
        })
        return try { block() } finally { ProxySelector.setDefault(original) }
    }

    private fun request(spec: JSONObject): Result<ServerHttp.Response> = runCatching {
        withFixtureProxy { ServerHttp.send(uri(spec), "POST", "application/json", body) }
    }

    private fun ordinaryRequest(spec: JSONObject): Result<ServerHttp.Response> = runCatching {
        withFixtureProxy {
            val connection = uri(spec).toURL().openConnection() as HttpsURLConnection
            try {
                connection.requestMethod = "POST"
                connection.connectTimeout = 5_000
                connection.readTimeout = 5_000
                connection.instanceFollowRedirects = false
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
                val status = connection.responseCode
                val stream = if (status in 200..299) connection.inputStream else connection.errorStream
                ServerHttp.Response(status, stream?.bufferedReader()?.use { it.readText() }.orEmpty())
            } finally { connection.disconnect() }
        }
    }

    private fun delta(id: String, before: JSONObject): JSONObject {
        val after = control("stats").getJSONObject(id)
        return JSONObject().apply {
            for (key in listOf("connections", "requests", "bytes")) put(key, after.getLong(key) - before.getLong(key))
        }
    }

    private fun record(id: String, result: Result<ServerHttp.Response>, stats: JSONObject, platform: Boolean? = null) {
        Log.i("KyAuthTLS", JSONObject().apply {
            put("control", controlPort); put("case", id); put("stats", stats)
            put("accepted", result.getOrNull()?.ok == true)
            put("error", result.exceptionOrNull()?.toString())
            if (platform != null) put("ordinary_accepted", platform)
        }.toString())
    }

    private fun assertRefused(id: String, result: Result<ServerHttp.Response>, stats: JSONObject) {
        assertTrue("$id must reach its TLS listener", stats.getLong("connections") > 0)
        assertTrue("$id unexpectedly succeeded", result.isFailure)
        assertEquals("$id received HTTP", 0L, stats.getLong("requests"))
        assertEquals("$id received application bytes", 0L, stats.getLong("bytes"))
    }

    @Test fun allPeersHonorKeyFloorAndNativeTrust() {
        val cases = control("cases")
        for (required in listOf("rsa2047", "rsa2048", "p256", "chain_root_rsa2047", "chain_intermediate_rsa2047", "trusted_rsa2047", "trusted_rsa2048", "invalid_hostname", "expired", "untrusted", "tls12", "tls13", "named", "named_wrong_host", "pinned")) {
            assertTrue("missing fixture $required", cases.has(required))
        }
        for (id in cases.keys().asSequence().toList().sorted()) {
            val spec = cases.getJSONObject(id)
            val kind = spec.getString("kind")
            if (kind == "certificate-only" || kind == "redirect") continue
            val ordinary = if (kind == "platform") ordinaryRequest(spec).getOrNull()?.ok == true else null
            if (id == "trusted_rsa2048") {
                assertTrue("direct-trust strong control refused; cannot credit weak-key refusals", ordinary == true)
            }
            val before = control("stats").getJSONObject(id)
            val result = request(spec)
            val stats = delta(id, before)
            record(id, result, stats, ordinary)
            val expected = when (kind) {
                "positive" -> true
                "weak", "trust" -> false
                "platform" -> ordinary == true && runCatching { ServerTls.meetsFloor(certificates(spec).first().publicKey) }.getOrDefault(false)
                else -> error("Unrecognized fixture kind $kind")
            }
            if (expected) {
                assertTrue("$id refused: ${result.exceptionOrNull()}", result.getOrThrow().ok)
                assertTrue("$id missing canary", JSONObject(result.getOrThrow().body).getBoolean("ok"))
                assertTrue("$id did not receive current HTTP", stats.getLong("requests") > 0)
                assertTrue("$id did not receive current bytes", stats.getLong("bytes") > 0)
            } else assertRefused(id, result, stats)
        }
    }

    @Test fun selectedPlatformPathIncludesItsAnchor() {
        val platform = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
            init(null as KeyStore?)
        }.trustManagers.filterIsInstance<X509ExtendedTrustManager>().single()
        assertEquals("android.security.net.config.RootTrustManager", platform.javaClass.name)
        val systemRoots = platform.acceptedIssuers
        assertTrue("system trust store is empty", systemRoots.isNotEmpty())
        for (root in systemRoots) {
            assertTrue("system anchor outside the supported floor: ${root.subjectX500Principal}", ServerTls.meetsFloor(root.publicKey))
        }
        Log.i("KyAuthTLS", "control=$controlPort system-anchors=${systemRoots.size} all-meet-floor=true")
        val extensions = X509TrustManagerExtensions(platform)
        val cases = control("cases")
        for (id in listOf("chain_strong", "chain_root_rsa2047", "chain_intermediate_rsa2047", "trusted_rsa2048")) {
            val spec = cases.getJSONObject(id)
            val wire = certificates(spec)
            val trusted = extensions.checkServerTrusted(wire, if (wire.first().publicKey is RSAPublicKey) "RSA" else "ECDHE_ECDSA", "127.0.0.1")
            val anchor = certificate(spec.getString("anchor"))
            assertArrayEquals("$id selected another anchor", anchor.encoded, trusted.last().encoded)
            if (spec.optBoolean("direct_trust")) {
                assertEquals(1, trusted.size)
                assertArrayEquals(wire.single().encoded, anchor.encoded)
            } else {
                assertEquals(wire.size + 1, trusted.size)
                assertFalse("$id anchor was on wire", wire.any { it.encoded.contentEquals(anchor.encoded) })
            }
            if (id == "chain_root_rsa2047") {
                assertEquals(2047, (trusted.last().publicKey as RSAPublicKey).modulus.bitLength())
                assertFalse(ServerTls.meetsFloor(trusted.last().publicKey))
            }
        }
    }

    @Test fun nativeCertificateAttributesDecideTheFloor() {
        val cases = control("cases")
        for (id in listOf("rsa1024", "rsa2047", "rsa2048", "p224", "p256", "p384")) {
            val key = certificates(cases.getJSONObject(id)).first().publicKey
            val expected = id in listOf("rsa2048", "p256", "p384")
            assertEquals(id, expected, ServerTls.meetsFloor(key))
            if (id == "rsa2047") assertEquals(2047, (key as RSAPublicKey).modulus.bitLength())
            if (id == "p224") assertEquals(224, (key as ECPublicKey).params.curve.field.fieldSize)
        }
        // P-521/Ed25519 parsing and TLS support vary independently between providers.
        for (id in listOf("p521", "ed25519")) {
            val key = runCatching { certificates(cases.getJSONObject(id)).first().publicKey }.getOrNull()
            if (id == "p521" && key is ECPublicKey) {
                assertEquals(521, key.params.curve.field.fieldSize)
                assertTrue(ServerTls.meetsFloor(key))
            }
            if (id == "ed25519" && key != null) assertFalse(ServerTls.meetsFloor(key))
            Log.i("KyAuthTLS", "control=$controlPort native-key=$id type=${key?.javaClass?.name}")
        }
    }

    @Test fun namesPinsAndRedirectRefusalRemainEnforced() {
        val cases = control("cases")
        for (id in listOf("named", "named_wrong_host", "pinned")) {
            val spec = cases.getJSONObject(id)
            val result = request(spec)
            if (id == "named") assertTrue(result.getOrThrow().ok) else assertTrue("$id accepted", result.isFailure)
            assertEquals("$id lost SNI", spec.getString("host"), control("sni").getString(id))
            if (id == "pinned") assertTrue("not a platform pin refusal", result.exceptionOrNull()?.stackTraceToString()?.contains("Pin verification failed") == true)
        }
        val before = control("stats").getJSONObject("redirect_target")
        val result = request(cases.getJSONObject("redirect")).getOrThrow()
        assertEquals(307, result.status)
        val target = delta("redirect_target", before)
        assertEquals("followed redirect", 0L, target.getLong("requests"))
        assertEquals("forwarded bytes", 0L, target.getLong("bytes"))
    }
}
