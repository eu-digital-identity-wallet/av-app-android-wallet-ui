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

package eu.europa.ec.authenticationlogic.storage

import eu.europa.ec.authenticationlogic.provider.PinStorageProvider
import eu.europa.ec.businesslogic.controller.storage.PrefsController
import eu.europa.ec.businesslogic.provider.BootIdProvider
import eu.europa.ec.businesslogic.provider.ElapsedRealtimeClock
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

class PrefsPinStorageProvider(
    private val prefsController: PrefsController,
    private val clock: ElapsedRealtimeClock,
    private val bootIdProvider: BootIdProvider,
) : PinStorageProvider {

    companion object {
        private const val KEY_PIN_HASH = "PinHash"
        private const val KEY_PIN_SALT = "PinSalt"
        private const val KEY_FAILED_ATTEMPTS = "PinFailedAttempts"
        private const val KEY_LOCKOUT_UNTIL = "PinLockoutUntil"
        private const val KEY_LOCKOUT_DURATION = "PinLockoutDurationMs"
        private const val KEY_LOCKOUT_BOOT_ID = "PinLockoutBootId"
        private const val PBKDF2_ITERATIONS = 210_000
        private const val KEY_LENGTH_BITS = 256
    }

    override fun hasPin(): Boolean {
        return prefsController.getString(KEY_PIN_HASH, "").isNotEmpty()
    }

    override fun setPin(pin: String) {
        val salt = generateSalt()
        val hash = hashPin(pin, salt)
        prefsController.setString(KEY_PIN_HASH, hash.toHexString())
        prefsController.setString(KEY_PIN_SALT, salt.toHexString())
        resetFailedAttempts()
    }

    override fun isPinValid(pin: String): Boolean {
        val storedHashHex = prefsController.getString(KEY_PIN_HASH, "")
        val saltHex = prefsController.getString(KEY_PIN_SALT, "")
        if (storedHashHex.isEmpty() || saltHex.isEmpty()) return false

        val salt = saltHex.hexToByteArray()
        val computedHash = hashPin(pin, salt)
        return MessageDigest.isEqual(computedHash, storedHashHex.hexToByteArray())
    }

    private fun hashPin(pin: String, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(pin.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS)
        return try {
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            factory.generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }

    private fun generateSalt(): ByteArray {
        val salt = ByteArray(32)
        SecureRandom().nextBytes(salt)
        return salt
    }

    private fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }

    private fun String.hexToByteArray(): ByteArray =
        try {
            chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        } catch (_: NumberFormatException) {
            ByteArray(0)
        }

    override fun getFailedAttempts(): Int {
        return prefsController.getInt(KEY_FAILED_ATTEMPTS, 0)
    }

    override fun incrementFailedAttempts(): Int {
        val currentAttempts = getFailedAttempts() + 1
        prefsController.setInt(KEY_FAILED_ATTEMPTS, currentAttempts)
        return currentAttempts
    }

    override fun resetFailedAttempts() {
        prefsController.setInt(KEY_FAILED_ATTEMPTS, 0)
        prefsController.setLong(KEY_LOCKOUT_UNTIL, 0L)
        prefsController.setLong(KEY_LOCKOUT_DURATION, 0L)
        prefsController.setString(KEY_LOCKOUT_BOOT_ID, "")
    }

    override fun setLockoutForDuration(durationMillis: Long) {
        prefsController.setLong(KEY_LOCKOUT_UNTIL, clock.now() + durationMillis)
        prefsController.setLong(KEY_LOCKOUT_DURATION, durationMillis)
        prefsController.setString(KEY_LOCKOUT_BOOT_ID, bootIdProvider.currentBootId())
    }

    /**
     * Returns the effective lockout deadline, re-anchoring after a reboot. Elapsed-realtime
     * resets on reboot, so a stale absolute deadline could either free the user early (bad) or
     * keep them locked for an unbounded interval (bad). Instead, on reboot we persist a fresh
     * `now + duration` deadline — the attacker gains nothing (they still wait a full duration),
     * and the legitimate user waits at most one extra full cycle.
     */
    override fun getLockoutUntil(): Long {
        val stored = prefsController.getLong(KEY_LOCKOUT_UNTIL, 0L)
        if (stored <= 0L) return 0L

        val storedBootId = prefsController.getString(KEY_LOCKOUT_BOOT_ID, "")
        val currentBootId = bootIdProvider.currentBootId()
        if (storedBootId.isNotEmpty() && storedBootId == currentBootId) {
            return stored
        }

        // Reboot (or missing boot id from an older install) — re-anchor the deadline
        val duration = prefsController.getLong(KEY_LOCKOUT_DURATION, 0L)
        if (duration <= 0L) {
            // Legacy entry without duration metadata: clear it and release the user
            prefsController.setLong(KEY_LOCKOUT_UNTIL, 0L)
            prefsController.setString(KEY_LOCKOUT_BOOT_ID, "")
            return 0L
        }
        val reanchored = clock.now() + duration
        prefsController.setLong(KEY_LOCKOUT_UNTIL, reanchored)
        prefsController.setString(KEY_LOCKOUT_BOOT_ID, currentBootId)
        return reanchored
    }

    override fun isCurrentlyLockedOut(): Boolean {
        val lockoutUntil = getLockoutUntil()
        return lockoutUntil > 0L && clock.now() < lockoutUntil
    }
}
