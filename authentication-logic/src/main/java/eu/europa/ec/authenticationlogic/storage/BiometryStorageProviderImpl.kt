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

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import eu.europa.ec.authenticationlogic.provider.BiometryStorageProvider
import eu.europa.ec.authenticationlogic.provider.VaultKeyProvider
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.businesslogic.controller.storage.PrefsController
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class BiometryStorageProviderImpl(
    private val prefsController: PrefsController,
    private val authMetadataStore: AuthMetadataStore,
    private val vaultKeyProvider: VaultKeyProvider,
    private val logController: LogController,
) : BiometryStorageProvider {

    companion object {
        private const val TAG = "PrefsBiometryStorageProvider"
        const val BIO_KEY_ALIAS = "av_pin_bio_v1"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val AES_GCM_NO_PADDING = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
    }

    override fun setUseBiometricsAuth(value: Boolean) {
        prefsController.setBool("UseBiometricsAuth", value)
    }

    override fun getUseBiometricsAuth(): Boolean {
        return prefsController.getBool("UseBiometricsAuth", false)
    }

    override suspend fun enrollBiometric(): Cipher = withContext(Dispatchers.IO) {
        val kBio = ensureBioKey()
        try {
            Cipher.getInstance(AES_GCM_NO_PADDING).apply {
                init(Cipher.ENCRYPT_MODE, kBio)
            }
        } catch (_: KeyPermanentlyInvalidatedException) {
            logController.d(TAG) { "Bio key invalidated, regenerating for enrollment" }
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
            ks.deleteEntry(BIO_KEY_ALIAS)
            val newKey = generateBioKey()
            Cipher.getInstance(AES_GCM_NO_PADDING).apply {
                init(Cipher.ENCRYPT_MODE, newKey)
            }
        }
    }

    override suspend fun commitBiometricEnrolment(cipher: Cipher) {
        val kVault = vaultKeyProvider.getVaultKey()
            ?: throw IllegalStateException("Vault key not available — PIN unlock required before biometric enrollment")
        try {
            val ciphertext = cipher.doFinal(kVault)
            val iv = cipher.iv
            val meta = authMetadataStore.read()
                ?: throw IllegalStateException("No auth metadata — cannot commit biometric enrolment")
            val updated = meta.copy(
                biometricEnabled = true,
                biometricWrappedVaultIv = iv,
                biometricWrappedVault = ciphertext,
            )
            authMetadataStore.write(updated)
        } finally {
            kVault.fill(0)
        }
    }

    override suspend fun prepareBiometricUnlock(): Cipher = withContext(Dispatchers.IO) {
        val meta = authMetadataStore.read()
            ?: throw IllegalStateException("No auth metadata")
        val iv = meta.biometricWrappedVaultIv
            ?: throw IllegalStateException("No biometric enrollment data")
        val kBio = getBioKey()
        try {
            Cipher.getInstance(AES_GCM_NO_PADDING).apply {
                init(Cipher.DECRYPT_MODE, kBio, GCMParameterSpec(GCM_TAG_BITS, iv))
            }
        } catch (_: KeyPermanentlyInvalidatedException) {
            logController.d(TAG) { "Bio key invalidated during unlock preparation" }
            handleBioKeyInvalidated()
            throw BiometricKeyInvalidatedException()
        }
    }

    override suspend fun completeBiometricUnlock(cipher: Cipher) {
        val meta = authMetadataStore.read()
            ?: throw IllegalStateException("No auth metadata")
        val ciphertext = meta.biometricWrappedVault
            ?: throw IllegalStateException("No biometric enrollment data")
        val kVault = cipher.doFinal(ciphertext)
        try {
            vaultKeyProvider.unlock(kVault)
        } finally {
            kVault.fill(0)
        }
    }

    private suspend fun handleBioKeyInvalidated() {
        withContext(Dispatchers.IO) {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
            ks.deleteEntry(BIO_KEY_ALIAS)
        }
        val meta = authMetadataStore.read()
        if (meta != null) {
            val updated = meta.copy(
                biometricEnabled = false,
                biometricWrappedVaultIv = null,
                biometricWrappedVault = null,
            )
            authMetadataStore.write(updated)
        }
    }

    private fun getBioKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
        return ks.getKey(BIO_KEY_ALIAS, null) as SecretKey
    }

    private fun ensureBioKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
        val existing = ks.getKey(BIO_KEY_ALIAS, null) as? SecretKey
        if (existing != null) return existing
        return generateBioKey()
    }

    @Suppress("DEPRECATION")
    private fun generateBioKey(): SecretKey {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            try {
                return generateBioKeySpec(tryStrongBox = true)
            } catch (_: Exception) {
                logController.d(TAG) { "StrongBox unavailable for bio key, falling back to TEE" }
            }
        }
        return generateBioKeySpec(tryStrongBox = false)
    }

    @Suppress("DEPRECATION")
    private fun generateBioKeySpec(tryStrongBox: Boolean): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE
        )
        val builder = KeyGenParameterSpec.Builder(
            BIO_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).apply {
            setKeySize(256)
            setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            setUserAuthenticationRequired(true)
            setInvalidatedByBiometricEnrollment(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            } else {
                setUserAuthenticationValidityDurationSeconds(-1)
            }
            if (tryStrongBox) {
                setIsStrongBoxBacked(true)
            }
        }
        keyGenerator.init(builder.build())
        return keyGenerator.generateKey()
    }
}
