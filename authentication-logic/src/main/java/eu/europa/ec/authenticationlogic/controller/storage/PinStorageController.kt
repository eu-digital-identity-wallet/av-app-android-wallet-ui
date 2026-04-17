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

package eu.europa.ec.authenticationlogic.controller.storage

import eu.europa.ec.authenticationlogic.config.StorageConfig

sealed class PinValidationResult {
    object Success : PinValidationResult()
    data class Failed(val attemptsRemaining: Int) : PinValidationResult()
    data class LockedOut(val lockoutEndTimeMillis: Long, val attemptsUsed: Int) :
        PinValidationResult()
}

interface PinStorageController {
    fun hasPin(): Boolean
    fun setPin(pin: String)
    fun isPinValid(pin: String): PinValidationResult
}

class PinStorageControllerImpl(private val storageConfig: StorageConfig) : PinStorageController {

    companion object {
        private const val MAX_ATTEMPTS = 4
        private const val BASE_LOCKOUT_DURATION_MS = 60 * 1000L // 1 minute
    }

    private val pinStorageProvider = storageConfig.pinStorageProvider

    override fun hasPin(): Boolean = pinStorageProvider.hasPin()

    override fun setPin(pin: String) {
        pinStorageProvider.setPin(pin)
    }

    override fun isPinValid(pin: String): PinValidationResult {
        if (pinStorageProvider.isCurrentlyLockedOut()) {
            return PinValidationResult.LockedOut(
                lockoutEndTimeMillis = pinStorageProvider.getLockoutUntil(),
                attemptsUsed = pinStorageProvider.getFailedAttempts()
            )
        }

        if (pinStorageProvider.isPinValid(pin)) {
            pinStorageProvider.resetFailedAttempts()
            return PinValidationResult.Success
        } else {
            val newAttemptCount = pinStorageProvider.incrementFailedAttempts()

            if (newAttemptCount >= MAX_ATTEMPTS) {
                val lockoutDuration = calculateLockoutDuration(newAttemptCount)
                val lockoutUntil = System.currentTimeMillis() + lockoutDuration

                pinStorageProvider.setLockoutUntil(lockoutUntil)

                return PinValidationResult.LockedOut(
                    lockoutEndTimeMillis = lockoutUntil,
                    attemptsUsed = newAttemptCount
                )
            } else {
                return PinValidationResult.Failed(
                    attemptsRemaining = MAX_ATTEMPTS - newAttemptCount
                )
            }
        }
    }

    private fun calculateLockoutDuration(attemptCount: Int): Long {
        // Progressive lockout times: 3=none, 4=1min, 5=5min, 6=15min, 7=1hr, 8=3hr, 9=8hr
        val multiplier = when (attemptCount) {
            4 -> 1      // 1 minute
            5 -> 5      // 5 minutes
            6 -> 15     // 15 minutes
            7 -> 60     // 1 hour
            8 -> 180    // 3 hours
            9 -> 480    // 8 hours
            else -> if (attemptCount > 9) 480 else 0  // 8 hours for any attempt beyond 9
        }
        return BASE_LOCKOUT_DURATION_MS * multiplier
    }
}
