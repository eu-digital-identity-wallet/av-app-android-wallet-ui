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
import eu.europa.ec.authenticationlogic.provider.VaultKeyProvider
import eu.europa.ec.businesslogic.controller.crypto.Argon2KeyDerivation
import eu.europa.ec.businesslogic.provider.BootIdProvider
import eu.europa.ec.businesslogic.provider.ElapsedRealtimeClock
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlinx.coroutines.runBlocking

class PinStorageProviderImpl(
    private val authMetadataStore: AuthMetadataStore,
    private val clock: ElapsedRealtimeClock,
    private val bootIdProvider: BootIdProvider,
    private val vaultKeyProvider: VaultKeyProvider,
) : PinStorageProvider {

    companion object {
        private const val GCM_TAG_BITS = 128
        private const val KDF_ALGO: Byte = 0x01
    }

    override fun hasPin(): Boolean = runBlocking { authMetadataStore.read() != null }

    override fun setPin(pin: String) {
        val pinChars = pin.toCharArray()
        try {
            val pinSalt = ByteArray(Argon2KeyDerivation.SALT_LEN)
                .also { SecureRandom().nextBytes(it) }
            val kPin = Argon2KeyDerivation.derive(pinChars, pinSalt)

            val existing = runBlocking { authMetadataStore.read() }

            if (existing != null && !vaultKeyProvider.isUnlocked()) {
                throw IllegalStateException("Vault must be unlocked to change the PIN")
            }

            val kVault: ByteArray = if (existing != null) {
                vaultKeyProvider.getVaultKey()!!
            } else {
                ByteArray(32).also { SecureRandom().nextBytes(it) }
            }
            val (wrappedVaultIv, wrappedVault) = aesGcmEncrypt(kPin, kVault, pinSalt)
            kPin.fill(0)
            if (existing == null) {
                vaultKeyProvider.unlock(kVault)
                kVault.fill(0)
            }
            val meta = existing?.copy(
                version = 0x01,
                kdfAlgo = KDF_ALGO,
                kdfM = Argon2KeyDerivation.M_COST_KIB,
                kdfT = Argon2KeyDerivation.T_COST,
                kdfP = Argon2KeyDerivation.PARALLELISM,
                pinSalt = pinSalt,
                wrappedVaultIv = wrappedVaultIv,
                wrappedVault = wrappedVault,
                failedAttempts = 0,
                lockoutDeadline = 0L,
                lockoutDuration = 0L,
                bootId = bootIdProvider.currentBootId(),
            ) ?: AuthMetadata(
                version = 0x01,
                kdfAlgo = KDF_ALGO,
                kdfM = Argon2KeyDerivation.M_COST_KIB,
                kdfT = Argon2KeyDerivation.T_COST,
                kdfP = Argon2KeyDerivation.PARALLELISM,
                pinSalt = pinSalt,
                wrappedVaultIv = wrappedVaultIv,
                wrappedVault = wrappedVault,
                bootId = bootIdProvider.currentBootId(),
            )
            runBlocking { authMetadataStore.write(meta) }
        } finally {
            pinChars.fill('\u0000')
        }
    }

    override fun isPinValid(pin: String): Boolean {
        val meta = readWithReanchor() ?: return false
        if (isLockedOutByMeta(meta)) return false
        val pinChars = pin.toCharArray()
        return try {
            val kPin = Argon2KeyDerivation.derive(
                pin = pinChars,
                salt = meta.pinSalt,
                mCostKib = meta.kdfM,
                tCost = meta.kdfT,
                parallelism = meta.kdfP,
            )
            val kVault = try {
                aesGcmDecrypt(kPin, meta.wrappedVault, meta.wrappedVaultIv, meta.pinSalt)
            } catch (_: Exception) {
                null
            } finally {
                kPin.fill(0)
            }
            if (kVault != null) {
                vaultKeyProvider.unlock(kVault)
                kVault.fill(0)
                true
            } else {
                false
            }
        } finally {
            pinChars.fill('\u0000')
        }
    }

    override fun getFailedAttempts(): Int = readWithReanchor()?.failedAttempts ?: 0

    override fun incrementFailedAttempts(): Int {
        val meta = readWithReanchor() ?: return 1
        val next = meta.failedAttempts + 1
        val updated = meta.copy(failedAttempts = next)
        runBlocking { authMetadataStore.write(updated) }
        return next
    }

    override fun resetFailedAttempts() {
        val meta = readWithReanchor() ?: return
        val updated = meta.copy(
            failedAttempts = 0,
            lockoutDeadline = 0L,
            lockoutDuration = 0L,
        )
        runBlocking { authMetadataStore.write(updated) }
    }

    override fun setLockoutForDuration(durationMillis: Long) {
        val meta = readWithReanchor() ?: return
        val updated = meta.copy(
            lockoutDeadline = clock.now() + durationMillis,
            lockoutDuration = durationMillis,
            bootId = bootIdProvider.currentBootId(),
        )
        runBlocking { authMetadataStore.write(updated) }
    }

    override fun getLockoutUntil(): Long {
        return readWithReanchor()?.lockoutDeadline ?: 0L
    }

    override fun isCurrentlyLockedOut(): Boolean {
        val meta = readWithReanchor() ?: return false
        return isLockedOutByMeta(meta)
    }

    private fun readWithReanchor(): AuthMetadata? {
        val meta = runBlocking { authMetadataStore.read() } ?: return null
        if (meta.lockoutDeadline > 0L && meta.bootId != bootIdProvider.currentBootId()) {
            val remaining = meta.lockoutDuration
            val reanchored = meta.copy(
                lockoutDeadline = clock.now() + remaining,
                bootId = bootIdProvider.currentBootId(),
            )
            runBlocking { authMetadataStore.write(reanchored) }
            return reanchored
        }
        return meta
    }

    private fun isLockedOutByMeta(meta: AuthMetadata): Boolean {
        return meta.lockoutDeadline > 0L && clock.now() < meta.lockoutDeadline
    }

    private fun aesGcmEncrypt(key: ByteArray, plaintext: ByteArray, aad: ByteArray): Pair<ByteArray, ByteArray> {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        cipher.updateAAD(aad)
        val ciphertext = cipher.doFinal(plaintext)
        return Pair(cipher.iv, ciphertext)
    }

    private fun aesGcmDecrypt(key: ByteArray, ciphertext: ByteArray, iv: ByteArray, aad: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }
}
