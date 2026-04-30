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

package eu.europa.ec.authenticationlogic.provider

interface PinStorageProvider {
    fun hasPin(): Boolean
    fun setPin(pin: String)
    fun isPinValid(pin: String): Boolean

    fun getFailedAttempts(): Int
    fun incrementFailedAttempts(): Int
    fun resetFailedAttempts()

    /**
     * Persist a lockout lasting [durationMillis] from the current elapsed-realtime clock.
     * Implementations must also record the current boot identity so the deadline can be
     * re-anchored after a reboot (see [getLockoutUntil]).
     */
    fun setLockoutForDuration(durationMillis: Long)

    /**
     * Returns the elapsed-realtime deadline at which the active lockout expires,
     * re-anchored to `now + durationMillis` if the device has rebooted since the
     * lockout was first set. Returns `0L` if no lockout is active.
     *
     * Boundary semantic: the user is locked out for `now < deadline` and released at
     * `now >= deadline`. Callers rendering a countdown must use the same `>=` boundary
     * (see `LockoutCountdownManager`) so that the UI's lockout-end signal agrees with
     * [isCurrentlyLockedOut].
     */
    fun getLockoutUntil(): Long

    /**
     * Returns true while `now < getLockoutUntil()`. The boundary instant itself is
     * treated as "released" — this matches the `>=` check in `LockoutCountdownManager`
     * so the UI never shows a 0-second countdown after the gate has opened.
     */
    fun isCurrentlyLockedOut(): Boolean
}