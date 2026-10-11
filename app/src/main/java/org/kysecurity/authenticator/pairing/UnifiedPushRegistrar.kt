package org.kysecurity.authenticator.pairing

import android.app.Activity
import android.content.Context
import androidx.appcompat.app.AlertDialog
import org.unifiedpush.android.connector.UnifiedPush
import org.unifiedpush.android.connector.data.ResolvedDistributor

/** UnifiedPush distributor selection. The endpoint arrives later, in KyAuthUnifiedPushService.onNewEndpoint. */
object UnifiedPushRegistrar {
    private const val INSTANCE = "default"
    const val NO_DISTRIBUTOR = "Install a UnifiedPush distributor such as ntfy, then try again."

    /** [show] presents the picker explanation; [onResult] gets null once registering, else a message for the user. */
    fun register(activity: Activity, show: (AlertDialog.Builder) -> Unit, onResult: (String?) -> Unit) {
        when (UnifiedPush.resolveDefaultDistributor(activity)) {
            is ResolvedDistributor.Found -> useDistributor(activity, onResult)
            ResolvedDistributor.NoneAvailable -> onResult(NO_DISTRIBUTOR)
            ResolvedDistributor.ToSelect -> show(
                AlertDialog.Builder(activity)
                    .setTitle("UnifiedPush")
                    .setMessage("Choose which app delivers KyAuth sign-in requests.")
                    .setPositiveButton("Choose") { _, _ -> useDistributor(activity, onResult) }
                    .setNegativeButton("Cancel") { _, _ -> onResult("No distributor was selected.") },
            )
        }
    }

    /** An explicit change: always shows the picker, even when a distributor is already in use. */
    fun pick(activity: Activity, onResult: (String?) -> Unit) {
        if (UnifiedPush.resolveDefaultDistributor(activity) == ResolvedDistributor.NoneAvailable) return onResult(NO_DISTRIBUTOR)
        UnifiedPush.tryPickDistributor(activity) { success ->
            if (success) UnifiedPush.register(activity, INSTANCE)
            onResult(if (success) null else "No distributor was selected.")
        }
    }

    private fun useDistributor(activity: Activity, onResult: (String?) -> Unit) {
        UnifiedPush.tryUseCurrentOrDefaultDistributor(activity) { success ->
            if (success) UnifiedPush.register(activity, INSTANCE)
            onResult(if (success) null else "No distributor was selected.")
        }
    }

    fun distributor(context: Context): String? = UnifiedPush.getAckDistributor(context)

    fun unregister(context: Context) = UnifiedPush.unregister(context, INSTANCE)
}
