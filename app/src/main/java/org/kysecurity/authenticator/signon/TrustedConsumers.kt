package org.kysecurity.authenticator.signon

import android.content.Context
import android.content.pm.PackageManager
import org.kysecurity.authenticator.BuildConfig
import java.security.MessageDigest

data class TrustedCaller(val packageName: String, val label: String)

/**
 * The apps allowed to ask for a KyIdentity sign-on token, by package and signing certificate.
 *
 * Package name alone proves nothing: anyone can build an APK named `org.kysecurity.mail`. The
 * SHA-256 of the signing certificate is what Android will not let an impostor forge. Every
 * package sharing the caller's UID must be pinned, because a shared UID reads the same
 * process memory.
 */
object TrustedConsumers {
    // SHA-256 of the DER signing certificate, lowercase hex: the Play App Signing key.
    // The org.kysecurity.mail.github flavor is unpinned until its digest is supplied.
    internal val PINS: Map<String, Set<String>> = mapOf(
        "org.kysecurity.mail" to setOf(
            "6f78411156058c1d27d5160699b73c0f45de266282383d8ca4361592e03a6c8e",
        ),
    )
    private val LABELS = mapOf(
        "org.kysecurity.mail" to "KyPost",
    )

    fun isTrusted(context: Context, callerUid: Int): TrustedCaller? {
        val pm = context.packageManager
        val packages = pm.getPackagesForUid(callerUid)?.toList().orEmpty()
        val debugDigest = BuildConfig.DEBUG_CONSUMER_CERT.takeIf { BuildConfig.DEBUG && it.isNotBlank() }
        return decide(packages, { pkg -> signingDigests(pm, pkg) }, debugDigest)
    }

    internal fun decide(
        packagesForUid: List<String>,
        certDigestsFor: (String) -> Set<String>,
        extraDebugDigest: String?,
    ): TrustedCaller? {
        if (packagesForUid.isEmpty()) return null
        for (pkg in packagesForUid) {
            val pinned = PINS[pkg] ?: return null
            val allowed = if (extraDebugDigest != null) pinned + extraDebugDigest else pinned
            val actual = certDigestsFor(pkg)
            if (actual.isEmpty() || !allowed.containsAll(actual)) return null
        }
        val first = packagesForUid.first()
        return TrustedCaller(first, LABELS.getValue(first))
    }

    private fun signingDigests(pm: PackageManager, pkg: String): Set<String> = runCatching {
        val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
        val signing = info.signingInfo ?: return emptySet()
        if (signing.hasMultipleSigners()) return emptySet()
        signing.signingCertificateHistory.map { sig ->
            MessageDigest.getInstance("SHA-256").digest(sig.toByteArray()).joinToString("") { "%02x".format(it) }
        }.toSet()
    }.getOrDefault(emptySet())
}
