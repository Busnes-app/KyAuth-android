package org.kysecurity.authenticator.pairing

import android.net.http.X509TrustManagerExtensions
import java.net.Socket
import java.security.KeyStore
import java.security.PublicKey
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedTrustManager

/** Per-connection policy; never changes the process-wide trust used by push SDKs. */
internal object ServerTls {
    val socketFactory: SSLSocketFactory by lazy {
        val managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
            init(null as KeyStore?)
        }.trustManagers
        val platform = managers.filterIsInstance<X509ExtendedTrustManager>().single()
        SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(StrongTrustManager(platform)), null)
        }.socketFactory
    }

    internal fun meetsFloor(key: PublicKey): Boolean = when (key) {
        is RSAPublicKey -> key.modulus.bitLength() >= 2048
        is ECPublicKey -> (key.params?.curve?.field?.fieldSize ?: 0) >= 256
        else -> false
    }

    private class StrongTrustManager(private val platform: X509ExtendedTrustManager) : X509ExtendedTrustManager() {
        private val extensions = X509TrustManagerExtensions(platform)

        private fun requireStrongChain(chain: Array<X509Certificate>, authType: String, host: String?) {
            if (host.isNullOrEmpty()) throw CertificateException("TLS peer hostname is unavailable")
            // The platform-built path includes its selected anchor; the wire chain may omit it.
            val trusted = extensions.checkServerTrusted(chain, authType, host)
            if (trusted.isEmpty() || trusted.any { !meetsFloor(it.publicKey) }) {
                throw CertificateException("TLS certificate key is below KyAuth's strength requirement")
            }
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, socket: Socket) {
            // Retain socket-aware platform checks before examining the verified chain.
            platform.checkServerTrusted(chain, authType, socket)
            requireStrongChain(chain, authType, (socket as? SSLSocket)?.handshakeSession?.peerHost)
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, engine: SSLEngine) {
            platform.checkServerTrusted(chain, authType, engine)
            requireStrongChain(chain, authType, engine.handshakeSession?.peerHost)
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            throw CertificateException("Hostname-aware TLS verification is required")
        }

        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) =
            platform.checkClientTrusted(chain, authType)
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String, socket: Socket) =
            platform.checkClientTrusted(chain, authType, socket)
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String, engine: SSLEngine) =
            platform.checkClientTrusted(chain, authType, engine)
        override fun getAcceptedIssuers(): Array<X509Certificate> = platform.acceptedIssuers
    }
}
