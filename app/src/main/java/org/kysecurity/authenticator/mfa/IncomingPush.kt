package org.kysecurity.authenticator.mfa

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import org.json.JSONObject
import org.kysecurity.authenticator.MainActivity
import org.kysecurity.authenticator.R
import org.kysecurity.authenticator.pairing.PairedAccount
import org.kysecurity.authenticator.pairing.PairingStore
import org.kysecurity.authenticator.pairing.PushKeys
import org.kysecurity.authenticator.pairing.PushStore

/** The one receive path for every push transport: parse, save, notify. */
object IncomingPush {
    private const val CHANNEL_ID = "kyauth_mfa_push"
    private const val RECONNECT_NOTIFICATION_ID = 1

    fun handle(context: Context, data: Map<String, String>) {
        val challenge = challenge(data, PairingStore(context).account()) ?: return
        MfaPushChallengeStore(context).save(challenge)
        notify(context, challenge.challengeId.hashCode(), "KyAuth sign-in request", "Tap to review the sign-in request.")
    }

    /** Only the paired server, device and account are accepted; anything else is null. */
    internal fun challenge(data: Map<String, String>, paired: PairedAccount?, nowMs: Long = System.currentTimeMillis()): MfaChallenge? =
        runCatching { MfaPushChallengeParser.parse(data, paired, nowMs) }.getOrNull()

    /** An FCM data message's challenge fields, opened with this pairing's keys; null when refused. */
    fun fcmData(context: Context, data: Map<String, String>): Map<String, String>? {
        val store = PushStore(context)
        return fcmData(data, if ("kyauth" in data) store.fcmKeys() else null, store.acceptsPlaintextFcm())
    }

    /**
     * A sealed push (`kyauth`, RFC 8291) opens only with [keys], and only its decrypted fields are
     * used. A plaintext push is accepted only when [plaintextAllowed] (KyIdentity holds no keys for
     * this device): otherwise the relay or Firebase could inject requests.
     */
    internal fun fcmData(data: Map<String, String>, keys: PushKeys?, plaintextAllowed: Boolean): Map<String, String>? {
        val sealed = data["kyauth"] ?: return data.takeIf { plaintextAllowed }
        if (keys == null) return null
        return runCatching { jsonData(WebPush.decrypt(PushKeys.unb64(sealed), keys)) }.getOrNull()
    }

    /** A decrypted push body: a flat JSON object of strings, else null. */
    internal fun jsonData(content: ByteArray): Map<String, String>? = runCatching {
        val json = JSONObject(String(content, Charsets.UTF_8))
        json.keys().asSequence().associateWith { json.get(it) as String }
    }.getOrNull()

    fun notifyReconnect(context: Context) =
        notify(context, RECONNECT_NOTIFICATION_ID, "Reconnect sign-in requests", "Open KyAuth to keep receiving sign-in requests.")

    fun ensureChannel(context: Context) {
        val channel = NotificationChannel(CHANNEL_ID, "KyAuth sign-in requests", NotificationManager.IMPORTANCE_HIGH)
        context.getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun notify(context: Context, id: Int, title: String, text: String) {
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        ensureChannel(context)
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_nav_lock)
            .setContentTitle(title)
            .setContentText(text)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()
        NotificationManagerCompat.from(context).notify(id, notification)
    }
}
