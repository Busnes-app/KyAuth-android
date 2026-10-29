package org.kysecurity.authenticator

import android.content.Intent
import android.os.Parcelable
import androidx.core.content.IntentCompat

/** Type-safe [Intent] extra lookup. */
inline fun <reified T : Parcelable> Intent.parcelable(name: String): T? =
    IntentCompat.getParcelableExtra(this, name, T::class.java)
