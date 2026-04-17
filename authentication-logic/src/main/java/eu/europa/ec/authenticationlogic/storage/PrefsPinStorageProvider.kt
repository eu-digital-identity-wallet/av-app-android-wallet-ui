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
import eu.europa.ec.businesslogic.controller.crypto.CryptoController
import eu.europa.ec.businesslogic.controller.storage.PrefsController
import eu.europa.ec.businesslogic.extension.decodeFromBase64
import eu.europa.ec.businesslogic.extension.encodeToBase64String
import java.security.MessageDigest

class PrefsPinStorageProvider(
    private val prefsController: PrefsController,
    private val cryptoController: CryptoController
) : PinStorageProvider {

    companion object {
        private const val KEY_DEVICE_PIN = "DevicePin"
        private const val KEY_FAILED_ATTEMPTS = "PinFailedAttempts"
        private const val KEY_LOCKOUT_UNTIL = "PinLockoutUntil"
    }

    /**
     * Checks whether a PIN has been stored.
     *
     * @return True if a non-blank PIN is stored, false otherwise.
     */
    override fun hasPin(): Boolean = decryptedAndLoad().isNotBlank()

    /**
     * Stores the given PIN in an encrypted format.
     * This method encrypts the provided PIN using cryptographic functions
     * and stores the encrypted data along with its initialization vector (IV)
     * in the preferences.
     *
     * @param pin The PIN to be stored.
     */
    override fun setPin(pin: String) {
        encryptAndStore(pin)
        resetFailedAttempts()
    }

    /**
     * Checks if the provided PIN is valid using constant-time comparison
     * to prevent timing side-channel attacks.
     *
     * @param pin The PIN to validate.
     * @return True if the provided PIN matches the stored PIN, false otherwise.
     */
    override fun isPinValid(pin: String): Boolean {
        val stored = decryptedAndLoad().toByteArray(Charsets.UTF_8)
        try {
            return MessageDigest.isEqual(stored, pin.toByteArray(Charsets.UTF_8))
        } finally {
            stored.fill(0)
        }
    }

    private fun encryptAndStore(pin: String) {

        val cipher = cryptoController.getCipher(
            encrypt = true,
            userAuthenticationRequired = false
        )

        val encryptedBytes = cryptoController.encryptDecrypt(
            cipher = cipher,
            byteArray = pin.toByteArray(Charsets.UTF_8)
        )

        val ivBytes = cipher?.iv ?: return

        prefsController.setString("PinEnc", encryptedBytes.encodeToBase64String())
        prefsController.setString("PinIv", ivBytes.encodeToBase64String())
    }

    private fun decryptedAndLoad(): String {

        val encryptedBase64 = prefsController.getString(
            "PinEnc", ""
        ).ifEmpty { return "" }

        val ivBase64 = prefsController.getString(
            "PinIv", ""
        ).ifEmpty { return "" }

        val cipher = cryptoController.getCipher(
            encrypt = false,
            ivBytes = decodeFromBase64(ivBase64),
            userAuthenticationRequired = false
        )

        val decryptedBytes = cryptoController.encryptDecrypt(
            cipher = cipher,
            byteArray = decodeFromBase64(encryptedBase64)
        )

        return String(decryptedBytes, Charsets.UTF_8)
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
    }

    override fun setLockoutUntil(timestampMillis: Long) {
        prefsController.setLong(KEY_LOCKOUT_UNTIL, timestampMillis)
    }

    override fun getLockoutUntil(): Long {
        return prefsController.getLong(KEY_LOCKOUT_UNTIL, 0L)
    }

    override fun isCurrentlyLockedOut(): Boolean {
        val lockoutUntil = getLockoutUntil()
        return lockoutUntil > 0L && System.currentTimeMillis() < lockoutUntil
    }
}