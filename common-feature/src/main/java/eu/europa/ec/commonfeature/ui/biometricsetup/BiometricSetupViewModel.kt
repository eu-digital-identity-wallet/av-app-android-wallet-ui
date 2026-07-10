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

package eu.europa.ec.commonfeature.ui.biometricsetup

import android.content.Context
import androidx.lifecycle.viewModelScope
import eu.europa.ec.authenticationlogic.controller.authentication.BiometricVaultResult.Cancelled
import eu.europa.ec.authenticationlogic.controller.authentication.BiometricVaultResult.Failed
import eu.europa.ec.authenticationlogic.controller.authentication.BiometricVaultResult.KeyInvalidated
import eu.europa.ec.authenticationlogic.controller.authentication.BiometricVaultResult.Success
import eu.europa.ec.authenticationlogic.controller.authentication.BiometricsAvailability.CanAuthenticate
import eu.europa.ec.authenticationlogic.controller.authentication.BiometricsAvailability.Failure
import eu.europa.ec.authenticationlogic.controller.authentication.BiometricsAvailability.NonEnrolled
import eu.europa.ec.commonfeature.interactor.BiometricInteractor
import eu.europa.ec.commonfeature.ui.biometricsetup.Effect.Navigation.SwitchScreen
import eu.europa.ec.commonfeature.ui.biometricsetup.Event.NextButtonPressed
import eu.europa.ec.commonfeature.ui.biometricsetup.Event.ScreenResumed
import eu.europa.ec.commonfeature.ui.biometricsetup.Event.SkipButtonPressed
import eu.europa.ec.corelogic.config.WalletCoreConfig
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.uilogic.component.content.ScreenNavigateAction
import eu.europa.ec.uilogic.mvi.MviViewModel
import eu.europa.ec.uilogic.mvi.ViewEvent
import eu.europa.ec.uilogic.mvi.ViewSideEffect
import eu.europa.ec.uilogic.mvi.ViewState
import eu.europa.ec.uilogic.navigation.OnboardingScreens
import kotlinx.coroutines.launch
import org.koin.android.annotation.KoinViewModel

sealed class Event : ViewEvent {
    data object ScreenResumed : Event()
    data class NextButtonPressed(val context: Context) : Event()
    data object SkipButtonPressed : Event()
}

data class State(
    val isLoading: Boolean = false,
    val isBiometricsAvailable: Boolean = false,
    val enrolled: Boolean = false,
    val biometricsError: String? = null,
    val isSetupMandatory: Boolean = false,
) : ViewState {
    val action: ScreenNavigateAction = ScreenNavigateAction.BACKABLE
}

sealed class Effect : ViewSideEffect {
    sealed class Navigation : Effect() {
        data class SwitchScreen(val screen: String) : Navigation()
    }
}

@KoinViewModel
class BiometricSetupViewModel(
    private val biometricInteractor: BiometricInteractor,
    private val resourceProvider: ResourceProvider,
    private val walletCoreConfig: WalletCoreConfig,
) : MviViewModel<Event, State, Effect>() {

    override fun setInitialState(): State {
        return State(
            isSetupMandatory = walletCoreConfig.userAuthenticationRequired
        )
    }

    override fun handleEvents(event: Event) {
        when (event) {
            is ScreenResumed -> {
                checkBiometricsAvailability()
            }

            is NextButtonPressed -> {
                clearError()
                if (viewState.value.isBiometricsAvailable) {
                    if (viewState.value.enrolled) {
                        enrollBiometric(event.context)
                    } else {
                        biometricInteractor.launchBiometricSystemScreen()
                    }
                }
            }

            is SkipButtonPressed -> {
                if (viewState.value.isSetupMandatory) {
                    return
                }
                biometricInteractor.storeBiometricsUsageDecision(false)
                navigateToNextScreen()
            }
        }
    }

    private fun enrollBiometric(context: Context) {
        viewModelScope.launch {
            when (val result = biometricInteractor.enrollBiometricVault(context)) {
                is Success -> authenticationSuccess()
                is Cancelled -> clearError()
                is Failed -> showError(result.errorMessage)
                is KeyInvalidated -> showError(resourceProvider.getString(R.string.biometric_key_invalidated))
            }
        }
    }

    private fun checkBiometricsAvailability() {
        setState { copy(isLoading = true) }
        biometricInteractor.getBiometricsAvailability { availability ->
            when (availability) {
                is CanAuthenticate -> {
                    setState {
                        copy(
                            isLoading = false,
                            isBiometricsAvailable = true,
                            enrolled = true,
                            biometricsError = null
                        )
                    }
                }

                is NonEnrolled -> {
                    setState {
                        copy(
                            isLoading = false,
                            isBiometricsAvailable = true,
                            enrolled = false,
                            biometricsError = null
                        )
                    }
                }

                is Failure -> {
                    val errorMessage = if (viewState.value.isSetupMandatory) {
                        resourceProvider.getString(R.string.biometric_setup_required_error)
                    } else {
                        availability.errorMessage
                    }
                    setState {
                        copy(
                            isLoading = false,
                            isBiometricsAvailable = false,
                            biometricsError = errorMessage
                        )
                    }
                }
            }
        }
    }

    private fun clearError() {
        setState { copy(biometricsError = null) }
    }

    private fun showError(error: String) {
        setState { copy(biometricsError = error) }
    }

    private fun authenticationSuccess() {
        biometricInteractor.storeBiometricsUsageDecision(true)
        navigateToNextScreen()
    }

    private fun navigateToNextScreen() {
        setEffect {
            SwitchScreen(OnboardingScreens.Enrollment.screenRoute)
        }
    }
}
