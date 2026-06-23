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

package eu.europa.ec.authenticationlogic.controller.authentication

import android.content.Intent
import android.content.Intent.FLAG_ACTIVITY_NEW_TASK
import android.provider.Settings
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.AuthenticationResult
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import eu.europa.ec.authenticationlogic.model.BiometricCrypto
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

enum class BiometricsAuthError(val code: Int) {
    Cancel(10), CancelByUser(13)
}

const val AUTHENTICATOR_LEVEL = BIOMETRIC_STRONG

interface BiometricAuthenticationController {
    fun deviceSupportsBiometrics(listener: (BiometricsAvailability) -> Unit)

    suspend fun authenticate(
        activity: FragmentActivity,
        biometryCrypto: BiometricCrypto,
        promptInfo: BiometricPrompt.PromptInfo,
        notifyOnAuthenticationFailure: Boolean,
    ): BiometricPromptData

    fun launchBiometricSystemScreen()
}

class BiometricAuthenticationControllerImpl(
    private val resourceProvider: ResourceProvider,
) : BiometricAuthenticationController {

    override fun deviceSupportsBiometrics(listener: (BiometricsAvailability) -> Unit) {
        val biometricManager = BiometricManager.from(resourceProvider.provideContext())
        when (biometricManager.canAuthenticate(AUTHENTICATOR_LEVEL)) {
            BiometricManager.BIOMETRIC_SUCCESS -> listener.invoke(BiometricsAvailability.CanAuthenticate)
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> listener.invoke(BiometricsAvailability.NonEnrolled)
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE, BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> listener.invoke(
                BiometricsAvailability.Failure(resourceProvider.getString(R.string.biometric_no_hardware))
            )

            else -> listener.invoke(BiometricsAvailability.Failure(resourceProvider.getString(R.string.biometric_unknown_error)))
        }
    }

    override fun launchBiometricSystemScreen() {
        val enrollIntent = Intent(Settings.ACTION_BIOMETRIC_ENROLL).apply {
            putExtra(
                Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED,
                AUTHENTICATOR_LEVEL
            )
        }
        enrollIntent.addFlags(FLAG_ACTIVITY_NEW_TASK)
        resourceProvider.provideContext().startActivity(enrollIntent)
    }

    override suspend fun authenticate(
        activity: FragmentActivity,
        biometryCrypto: BiometricCrypto,
        promptInfo: BiometricPrompt.PromptInfo,
        notifyOnAuthenticationFailure: Boolean
    ): BiometricPromptData = suspendCancellableCoroutine { continuation ->
        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (continuation.isActive) {
                        continuation.resume(
                            BiometricPromptData(null, errorCode, errString)
                        )
                    }
                }

                override fun onAuthenticationSucceeded(result: AuthenticationResult) {
                    if (continuation.isActive) {
                        continuation.resume(BiometricPromptData(result))
                    }
                }

                override fun onAuthenticationFailed() {
                    if (continuation.isActive && notifyOnAuthenticationFailure) {
                        continuation.resume(BiometricPromptData(null))
                    }
                }
            }
        )
        biometryCrypto.cryptoObject?.let {
            prompt.authenticate(
                promptInfo,
                it
            )
        } ?: prompt.authenticate(promptInfo)
    }
}

sealed class BiometricVaultResult {
    data object Success : BiometricVaultResult()
    data class Failed(val errorMessage: String) : BiometricVaultResult()
    data object Cancelled : BiometricVaultResult()
    data object KeyInvalidated : BiometricVaultResult()
}

sealed class BiometricsAvailability {
    data object CanAuthenticate : BiometricsAvailability()
    data object NonEnrolled : BiometricsAvailability()
    data class Failure(val errorMessage: String) : BiometricsAvailability()
}

data class BiometricPromptData(
    val authenticationResult: AuthenticationResult?,
    val errorCode: Int = -1,
    val errorString: CharSequence = "",
) {
    val hasError: Boolean get() = errorCode != -1
}
