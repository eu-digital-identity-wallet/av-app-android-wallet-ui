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
import javax.crypto.Cipher

interface BiometryStorageController {
    fun setUseBiometricsAuth(value: Boolean)
    fun getUseBiometricsAuth(): Boolean
    suspend fun enrollBiometric(): Cipher
    suspend fun commitBiometricEnrolment(cipher: Cipher)
    suspend fun prepareBiometricUnlock(): Cipher
    suspend fun completeBiometricUnlock(cipher: Cipher)
}

class BiometryStorageControllerImpl(private val storageConfig: StorageConfig) :
    BiometryStorageController {
    override fun setUseBiometricsAuth(value: Boolean) {
        storageConfig.biometryStorageProvider.setUseBiometricsAuth(value)
    }

    override fun getUseBiometricsAuth(): Boolean =
        storageConfig.biometryStorageProvider.getUseBiometricsAuth()

    override suspend fun enrollBiometric(): Cipher =
        storageConfig.biometryStorageProvider.enrollBiometric()

    override suspend fun commitBiometricEnrolment(cipher: Cipher) =
        storageConfig.biometryStorageProvider.commitBiometricEnrolment(cipher)

    override suspend fun prepareBiometricUnlock(): Cipher =
        storageConfig.biometryStorageProvider.prepareBiometricUnlock()

    override suspend fun completeBiometricUnlock(cipher: Cipher) =
        storageConfig.biometryStorageProvider.completeBiometricUnlock(cipher)
}
