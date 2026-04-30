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

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import eu.europa.ec.authenticationlogic.model.BiometricCrypto
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import kotlinx.coroutines.launch

interface DeviceAuthenticationController {
    fun deviceSupportsBiometrics(listener: (BiometricsAvailability) -> Unit)
    fun authenticate(
        context: Context,
        biometryCrypto: BiometricCrypto,
        notifyOnAuthenticationFailure: Boolean,
        result: DeviceAuthenticationResult
    )

    fun launchBiometricSystemScreen()
}

class DeviceAuthenticationControllerImpl(
    private val resourceProvider: ResourceProvider,
    private val biometricAuthenticationController: BiometricAuthenticationController
) : DeviceAuthenticationController {

    override fun deviceSupportsBiometrics(listener: (BiometricsAvailability) -> Unit) {
        biometricAuthenticationController.deviceSupportsBiometrics(listener)
    }

    override fun authenticate(
        context: Context,
        biometryCrypto: BiometricCrypto,
        notifyOnAuthenticationFailure: Boolean,
        result: DeviceAuthenticationResult
    ) {
        (context as? FragmentActivity)?.let { activity ->

            activity.lifecycleScope.launch {

                val data = biometricAuthenticationController.authenticate(
                    activity = activity,
                    biometryCrypto = biometryCrypto,
                    promptInfo = BiometricPrompt.PromptInfo.Builder()
                        .setTitle(resourceProvider.getString(R.string.biometric_prompt_title))
                        .setSubtitle(resourceProvider.getString(R.string.biometric_prompt_subtitle))
                        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                        .build(),
                    notifyOnAuthenticationFailure = notifyOnAuthenticationFailure
                )

                if (data.authenticationResult != null) {
                    result.onAuthenticationSuccess()
                } else if (data.hasError) {
                    result.onAuthenticationError()
                } else {
                    result.onAuthenticationFailure()
                }
            }
        }
    }

    override fun launchBiometricSystemScreen() {
        biometricAuthenticationController.launchBiometricSystemScreen()
    }
}

data class DeviceAuthenticationResult(
    val onAuthenticationSuccess: suspend () -> Unit = {},
    val onAuthenticationError: () -> Unit = {},
    val onAuthenticationFailure: () -> Unit = {},
)