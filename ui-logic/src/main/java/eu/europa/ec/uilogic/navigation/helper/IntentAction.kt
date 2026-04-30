/*
 * Copyright (c) 2025 European Commission
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European
 * Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work
 * except in compliance with the Licence.
 *
 * You may obtain a copy of the Licence at:
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the Licence for the specific language
 * governing permissions and limitations under the Licence.
 */

package eu.europa.ec.uilogic.navigation.helper

import android.content.Intent
import eu.europa.ec.businesslogic.provider.ElapsedRealtimeClock

data class IntentAction(val intent: Intent)

private const val ACTION_GET_CREDENTIAL =
    "androidx.credentials.registry.provider.action.GET_CREDENTIAL"
private const val ACTION_GET_CREDENTIALS = "androidx.identitycredentials.action.GET_CREDENTIALS"

// Intents older than this threshold are discarded to prevent stale-intent replay
private const val INTENT_MAX_AGE_MS = 60_000L

/**
 * Temporary storage for DCAPI intent to make it accessible across the app lifecycle.
 * The intent is timestamped on caching so stale entries cannot be replayed after
 * a failed or abandoned authentication attempt.
 */
class DcApiIntentHolder(private val clock: ElapsedRealtimeClock) {
    private var cachedIntent: Intent? = null
    private var cachedAtElapsed: Long = 0L

    @Synchronized
    fun cacheIntent(intent: Intent?) {
        cachedIntent = intent
        cachedAtElapsed = if (intent != null) clock.now() else 0L
    }

    @Synchronized
    fun retrieveIntent(): Intent? {
        val intent = cachedIntent ?: return null
        val age = clock.now() - cachedAtElapsed
        cachedIntent = null
        cachedAtElapsed = 0L
        return if (age <= INTENT_MAX_AGE_MS) intent else null
    }
}

fun isDCAPIIntent(intent: Intent?): Boolean {
    return intent?.action == ACTION_GET_CREDENTIAL || intent?.action == ACTION_GET_CREDENTIALS
}
