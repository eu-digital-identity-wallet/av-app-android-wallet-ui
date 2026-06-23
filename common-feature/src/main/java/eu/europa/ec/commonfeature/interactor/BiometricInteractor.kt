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

package eu.europa.ec.commonfeature.interactor

import android.content.Context
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import eu.europa.ec.authenticationlogic.controller.authentication.BiometricAuthenticationController
import eu.europa.ec.authenticationlogic.controller.authentication.BiometricVaultResult
import eu.europa.ec.authenticationlogic.controller.authentication.BiometricsAuthError.Cancel
import eu.europa.ec.authenticationlogic.controller.authentication.BiometricsAuthError.CancelByUser
import eu.europa.ec.authenticationlogic.controller.authentication.BiometricsAvailability
import eu.europa.ec.authenticationlogic.controller.storage.BiometryStorageController
import eu.europa.ec.authenticationlogic.model.BiometricCrypto
import eu.europa.ec.authenticationlogic.storage.BiometricKeyInvalidatedException
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import kotlinx.coroutines.flow.Flow

interface BiometricInteractor {
    fun getBiometricsAvailability(listener: (BiometricsAvailability) -> Unit)
    fun getBiometricUserSelection(): Boolean
    fun storeBiometricsUsageDecision(shouldUseBiometrics: Boolean)
    suspend fun enrollBiometricVault(context: Context): BiometricVaultResult
    suspend fun unlockWithBiometrics(context: Context): BiometricVaultResult
    fun launchBiometricSystemScreen()
    fun isPinValid(pin: String): Flow<QuickPinInteractorPinValidPartialState>
}

class BiometricInteractorImpl(
    private val biometryStorageController: BiometryStorageController,
    private val biometricAuthenticationController: BiometricAuthenticationController,
    private val resourceProvider: ResourceProvider,
    private val quickPinInteractor: QuickPinInteractor,
) : BiometricInteractor {

    override fun isPinValid(pin: String): Flow<QuickPinInteractorPinValidPartialState> =
        quickPinInteractor.isCurrentPinValid(pin)

    override fun storeBiometricsUsageDecision(shouldUseBiometrics: Boolean) {
        biometryStorageController.setUseBiometricsAuth(shouldUseBiometrics)
    }

    override fun getBiometricUserSelection(): Boolean {
        return biometryStorageController.getUseBiometricsAuth()
    }

    override fun getBiometricsAvailability(listener: (BiometricsAvailability) -> Unit) {
        biometricAuthenticationController.deviceSupportsBiometrics(listener)
    }

    override suspend fun enrollBiometricVault(context: Context): BiometricVaultResult {
        val activity = context as? FragmentActivity
            ?: return BiometricVaultResult.Failed("Activity context required")

        val cipher = try {
            biometryStorageController.enrollBiometric()
        } catch (_: Exception) {
            return BiometricVaultResult.Failed(
                resourceProvider.getString(R.string.generic_error_description)
            )
        }

        val promptInfo = buildVaultPromptInfo()
        val crypto = BiometricCrypto(BiometricPrompt.CryptoObject(cipher))
        val data = biometricAuthenticationController.authenticate(
            activity = activity,
            biometryCrypto = crypto,
            promptInfo = promptInfo,
            notifyOnAuthenticationFailure = true
        )

        return when {
            data.authenticationResult != null -> {
                try {
                    biometryStorageController.commitBiometricEnrolment(cipher)
                    BiometricVaultResult.Success
                } catch (_: Exception) {
                    BiometricVaultResult.Failed(
                        resourceProvider.getString(R.string.generic_error_description)
                    )
                }
            }

            data.errorCode == Cancel.code || data.errorCode == CancelByUser.code -> {
                BiometricVaultResult.Cancelled
            }

            else -> BiometricVaultResult.Failed(data.errorString.toString())
        }
    }

    override suspend fun unlockWithBiometrics(context: Context): BiometricVaultResult {
        val activity = context as? FragmentActivity
            ?: return BiometricVaultResult.Failed("Activity context required")

        val cipher = try {
            biometryStorageController.prepareBiometricUnlock()
        } catch (_: BiometricKeyInvalidatedException) {
            return BiometricVaultResult.KeyInvalidated
        } catch (_: Exception) {
            return BiometricVaultResult.Failed(
                resourceProvider.getString(R.string.generic_error_description)
            )
        }

        val promptInfo = buildVaultPromptInfo()
        val crypto = BiometricCrypto(BiometricPrompt.CryptoObject(cipher))
        val data = biometricAuthenticationController.authenticate(
            activity = activity,
            biometryCrypto = crypto,
            promptInfo = promptInfo,
            notifyOnAuthenticationFailure = true
        )

        return when {
            data.authenticationResult != null -> {
                try {
                    biometryStorageController.completeBiometricUnlock(cipher)
                    BiometricVaultResult.Success
                } catch (_: Exception) {
                    BiometricVaultResult.Failed(
                        resourceProvider.getString(R.string.generic_error_description)
                    )
                }
            }

            data.errorCode == Cancel.code ||
                    data.errorCode == CancelByUser.code -> {
                BiometricVaultResult.Cancelled
            }

            else -> BiometricVaultResult.Failed(data.errorString.toString())
        }
    }

    override fun launchBiometricSystemScreen() {
        biometricAuthenticationController.launchBiometricSystemScreen()
    }

    private fun buildVaultPromptInfo(): BiometricPrompt.PromptInfo {
        return BiometricPrompt.PromptInfo.Builder()
            .setTitle(resourceProvider.getString(R.string.biometric_prompt_title))
            .setSubtitle(resourceProvider.getString(R.string.biometric_prompt_subtitle))
            .setNegativeButtonText(resourceProvider.getString(R.string.generic_cancel))
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            .build()
    }
}
