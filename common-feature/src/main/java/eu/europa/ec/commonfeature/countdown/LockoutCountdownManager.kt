/*
 * Copyright (c) 2023 European Commission
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

package eu.europa.ec.commonfeature.countdown

import eu.europa.ec.businesslogic.provider.ElapsedRealtimeClock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlin.time.Duration.Companion.seconds

class LockoutCountdownManager(
    private val coroutineScope: CoroutineScope,
    private val clock: ElapsedRealtimeClock,
    private val getIsLockedOut: () -> Boolean,
    private val getLockoutEndTime: () -> Long,
    private val onCountdownUpdate: (String?) -> Unit,
    private val onLockoutEnd: () -> Unit,
    private val getTimeMessage: (minutes: Long, seconds: Long) -> String
) {
    private var job: Job? = null

    fun start() {
        job?.cancel()
        job = coroutineScope.launch {
            // Boundary: the storage layer treats `now >= deadline` as released.
            // Mirror that here so the countdown fires onLockoutEnd at the exact instant
            // PinStorageProvider.isCurrentlyLockedOut() would flip to false.
            while (getIsLockedOut()) {
                val currentTime = clock.now()
                val lockoutEndTime = getLockoutEndTime()

                if (currentTime >= lockoutEndTime) {
                    onLockoutEnd()
                    break
                }

                val remainingSeconds = (lockoutEndTime - currentTime) / 1000
                val minutes = remainingSeconds / 60
                val seconds = remainingSeconds % 60
                val message = getTimeMessage(minutes, seconds)
                onCountdownUpdate(message)
                delay(1.seconds)
            }
        }
    }

    fun cancel() {
        job?.cancel()
    }
}
