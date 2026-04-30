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

package eu.europa.ec.onboardingfeature.session

import android.graphics.Bitmap
import java.util.concurrent.ConcurrentHashMap

/**
 * Holds the passport face bitmap in memory for the duration of the passport onboarding flow.
 */
class PassportOnboardingSession {

    private val bitmaps = ConcurrentHashMap<String, Bitmap>()

    fun put(sessionId: String, bitmap: Bitmap) {
        bitmaps[sessionId] = ensureMutable(bitmap)
    }

    fun get(sessionId: String): Bitmap? = bitmaps[sessionId]

    fun remove(sessionId: String) {
        bitmaps.remove(sessionId)?.let(::zeroAndRecycle)
    }

    fun clear() {
        bitmaps.values.forEach(::zeroAndRecycle)
        bitmaps.clear()
    }

    // Bitmap.recycle() does not overwrite the backing pixel memory, so an in-process heap dump
    // could still read the face image. Keeping the bitmap mutable lets us overwrite with zeros
    // before releasing the reference.
    private fun ensureMutable(bitmap: Bitmap): Bitmap {
        if (bitmap.isMutable) return bitmap
        val mutable = bitmap.copy(Bitmap.Config.ARGB_8888, true)
        bitmap.recycle()
        return mutable
    }

    private fun zeroAndRecycle(bitmap: Bitmap) {
        if (bitmap.isRecycled) return
        if (bitmap.isMutable) {
            runCatching { bitmap.eraseColor(0) }
        }
        bitmap.recycle()
    }
}
