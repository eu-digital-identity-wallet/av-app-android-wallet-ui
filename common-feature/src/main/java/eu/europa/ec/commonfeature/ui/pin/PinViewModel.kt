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

package eu.europa.ec.commonfeature.ui.pin

import androidx.lifecycle.viewModelScope
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.businesslogic.validator.Form
import eu.europa.ec.businesslogic.validator.FormValidationResult
import eu.europa.ec.businesslogic.validator.Rule
import eu.europa.ec.commonfeature.config.IssuanceFlowType
import eu.europa.ec.commonfeature.config.IssuanceUiConfig
import eu.europa.ec.commonfeature.config.SuccessUIConfig
import eu.europa.ec.commonfeature.countdown.LockoutCountdownManager
import eu.europa.ec.commonfeature.interactor.QuickPinInteractor
import eu.europa.ec.commonfeature.interactor.QuickPinInteractorPinValidPartialState
import eu.europa.ec.commonfeature.interactor.QuickPinInteractorSetPinPartialState
import eu.europa.ec.commonfeature.model.PinFlow
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.uilogic.component.content.ScreenNavigateAction
import eu.europa.ec.uilogic.config.ConfigNavigation
import eu.europa.ec.uilogic.config.NavigationType
import eu.europa.ec.uilogic.mvi.MviViewModel
import eu.europa.ec.uilogic.mvi.ViewEvent
import eu.europa.ec.uilogic.mvi.ViewSideEffect
import eu.europa.ec.uilogic.mvi.ViewState
import eu.europa.ec.uilogic.navigation.CommonScreens
import eu.europa.ec.uilogic.navigation.CommonScreens.BiometricSetup
import eu.europa.ec.uilogic.navigation.LandingScreens
import eu.europa.ec.uilogic.navigation.helper.generateComposableArguments
import eu.europa.ec.uilogic.navigation.helper.generateComposableNavigationLink
import eu.europa.ec.uilogic.serializer.UiSerializer
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.koin.android.annotation.KoinViewModel
import org.koin.core.annotation.InjectedParam

enum class PinValidationState {
    ENTER,
    REENTER,
    VALIDATE
}

data class State(
    val pinFlow: PinFlow,
    val isLoading: Boolean = false,
    val isButtonEnabled: Boolean = false,
    val quickPinError: String? = null,
    val validationResult: FormValidationResult = FormValidationResult(false),
    val subtitle: String = "",
    val title: String = "",
    val pin: String = "",
    val enteredPin: String = "",
    val buttonText: String = "",
    val resetPin: Boolean = false,
    val pinState: PinValidationState,
    val isBottomSheetOpen: Boolean = false,
    val quickPinSize: Int = 6,
    val isLockedOut: Boolean = false,
    val lockoutEndTime: Long = 0L,
) : ViewState {
    val action: ScreenNavigateAction
        get() {
            return when {
                pinState == PinValidationState.REENTER -> ScreenNavigateAction.BACKABLE
                pinFlow == PinFlow.UPDATE -> ScreenNavigateAction.CANCELABLE
                else -> ScreenNavigateAction.NONE
            }
        }

    val onBackEvent: Event
        get() {
            return when {
                pinState == PinValidationState.REENTER -> Event.GoBack
                pinFlow == PinFlow.UPDATE -> Event.CancelPressed
                else -> Event.GoBack
            }
        }
}

sealed class Event : ViewEvent {
    data class NextButtonPressed(val pin: String) : Event()
    data class OnQuickPinEntered(val quickPin: String) : Event()
    data object CancelPressed : Event()
    data object GoBack : Event()
    sealed class BottomSheet : Event() {
        data class UpdateBottomSheetState(val isOpen: Boolean) : BottomSheet()

        sealed class Cancel : BottomSheet() {
            data object DiscardPressed : Cancel()
            data object ConfirmCancelPressed : Cancel()
        }
    }
}

sealed class Effect : ViewSideEffect {
    sealed class Navigation : Effect() {
        data class SwitchScreen(val screen: String) : Navigation()
        data object Pop : Navigation()
    }

    data object ShowBottomSheet : Effect()
    data object CloseBottomSheet : Effect()
}

@KoinViewModel
class PinViewModel(
    private val interactor: QuickPinInteractor,
    private val resourceProvider: ResourceProvider,
    private val uiSerializer: UiSerializer,
    private val logController: LogController,
    @InjectedParam private val pinFlow: PinFlow,
) : MviViewModel<Event, State, Effect>() {

    private val lockoutCountdownManager = LockoutCountdownManager(
        coroutineScope = viewModelScope,
        getIsLockedOut = { viewState.value.isLockedOut },
        getLockoutEndTime = { viewState.value.lockoutEndTime },
        onCountdownUpdate = { message ->
            setState {
                copy(
                    quickPinError = message,
                )
            }
        },
        onLockoutEnd = {
            setState { copy(isLockedOut = false, quickPinError = null, lockoutEndTime = 0L) }
        },
        getTimeMessage = { minutes, seconds ->
            if (minutes > 0)
                resourceProvider.getString(
                    R.string.quick_pin_change_lockout_countdown_minutes,
                    minutes,
                    seconds
                )
            else
                resourceProvider.getString(R.string.quick_pin_change_lockout_countdown_seconds, seconds)
        },
        logController = logController
    )

    override fun setInitialState(): State {
        val title: String
        val subtitle: String
        val pinState: PinValidationState
        val buttonText: String

        when (pinFlow) {
            PinFlow.CREATE -> {
                title = resourceProvider.getString(R.string.quick_pin_create_title)
                subtitle = resourceProvider.getString(R.string.quick_pin_create_enter_subtitle)
                pinState = PinValidationState.ENTER
                buttonText = calculateButtonText(pinState)
            }

            PinFlow.UPDATE -> {
                title = resourceProvider.getString(R.string.quick_pin_change_title)
                subtitle =
                    resourceProvider.getString(R.string.quick_pin_change_validate_current_subtitle)
                pinState = PinValidationState.VALIDATE
                buttonText = calculateButtonText(pinState)
            }
        }

        return State(
            isLoading = false,
            title = title,
            subtitle = subtitle,
            pinState = pinState,
            buttonText = buttonText,
            pinFlow = pinFlow
        )
    }

    override fun handleEvents(event: Event) {
        when (event) {
            is Event.OnQuickPinEntered -> {
                // Don't process PIN input during lockout
                if (viewState.value.isLockedOut) {
                    return
                }
                validateForm(event.quickPin)
            }

            is Event.NextButtonPressed -> {
                val state = viewState.value
                when (state.pinState) {
                    PinValidationState.ENTER -> {
                        // Set state for re-enter phase
                        setupReenterPhase(enteredPin = event.pin)
                    }

                    PinValidationState.REENTER -> {
                        // Save the new pin
                        saveNewPin(newPin = state.pin, enteredPin = state.enteredPin)
                    }

                    PinValidationState.VALIDATE -> {
                        validatePin(currentPin = state.pin)
                    }
                }
            }

            is Event.CancelPressed -> {
                showBottomSheet()
            }

            is Event.BottomSheet.UpdateBottomSheetState -> {
                setState {
                    copy(isBottomSheetOpen = event.isOpen)
                }
            }

            is Event.BottomSheet.Cancel.DiscardPressed -> {
                hideBottomSheet()
            }

            is Event.BottomSheet.Cancel.ConfirmCancelPressed -> {
                viewModelScope.launch {
                    hideBottomSheet()
                    delay(200L)
                    setEffect { Effect.Navigation.Pop }
                }
            }

            is Event.GoBack -> {
                if (viewState.value.pinState == PinValidationState.REENTER) {
                    setupEnterPhaseFromReenter()
                } else {
                    setEffect { Effect.Navigation.Pop }
                }
            }
        }
    }

    private fun validatePin(currentPin: String) {
        viewModelScope.launch {
            interactor.isCurrentPinValid(
                pin = currentPin
            ).collect {
                when (it) {
                    is QuickPinInteractorPinValidPartialState.Failed -> {
                        setState {
                            copy(
                                quickPinError = it.errorMessage,
                                isLockedOut = false,
                            )
                        }
                    }

                    QuickPinInteractorPinValidPartialState.Success -> {
                        setupEnterPhase()
                    }

                    is QuickPinInteractorPinValidPartialState.LockedOut -> {
                        setState {
                            copy(
                                isLockedOut = true,
                                lockoutEndTime = it.lockoutEndTime,
                                quickPinError = resourceProvider.getString(R.string.quick_pin_locked_out)
                            )
                        }
                        lockoutCountdownManager.start()
                    }
                }
            }
        }
    }

    private fun setupEnterPhase() {
        val newPinState = PinValidationState.ENTER

        setState {
            copy(
                quickPinError = null,
                enteredPin = "",
                pinState = newPinState,
                buttonText = calculateButtonText(newPinState),
                pin = "",
                isButtonEnabled = false,
                resetPin = true,
                subtitle = calculateSubtitle(newPinState),
                isLockedOut = false,
            )
        }
    }

    private fun setupReenterPhase(enteredPin: String) {
        val newPinState = PinValidationState.REENTER

        setState {
            copy(
                quickPinError = null,
                enteredPin = enteredPin,
                pinState = PinValidationState.REENTER,
                buttonText = calculateButtonText(newPinState),
                pin = "",
                isButtonEnabled = false,
                resetPin = true,
                subtitle = calculateSubtitle(newPinState),
                title = calculateTitle(newPinState)
            )
        }
    }

    private fun setupEnterPhaseFromReenter() {
        val newPinState = PinValidationState.ENTER

        setState {
            copy(
                quickPinError = null,
                enteredPin = "",
                pinState = newPinState,
                buttonText = calculateButtonText(newPinState),
                pin = "",
                isButtonEnabled = false,
                resetPin = true,
                subtitle = calculateSubtitle(newPinState),
                title = calculateTitle(newPinState),
            )
        }
    }

    private fun calculateTitle(pinState: PinValidationState): String {
        return when (pinState) {
            PinValidationState.ENTER -> resourceProvider.getString(R.string.quick_pin_create_title)
            PinValidationState.REENTER -> resourceProvider.getString(R.string.quick_pin_create_reenter_title)
            PinValidationState.VALIDATE -> viewState.value.title
        }
    }

    private fun saveNewPin(newPin: String, enteredPin: String) {
        viewModelScope.launch {
            interactor.setPin(
                newPin = newPin,
                initialPin = enteredPin
            ).collect {
                when (it) {
                    is QuickPinInteractorSetPinPartialState.Failed -> {
                        setState {
                            copy(
                                quickPinError = it.errorMessage
                            )
                        }
                    }

                    is QuickPinInteractorSetPinPartialState.Success -> {
                        setEffect {
                            Effect.Navigation.SwitchScreen(getNextScreenRoute())
                        }
                    }
                }
            }
        }
    }

    private fun getListOfRules(pin: String): Form {
        return Form(
            mapOf(
                listOf(
                    Rule.ValidateStringRange(
                        viewState.value.quickPinSize..viewState.value.quickPinSize,
                        ""
                    ),
                    Rule.ValidateRegex(
                        "-?\\d+(\\.\\d+)?".toRegex(),
                        resourceProvider.getString(R.string.quick_pin_numerical_rule_invalid_error_message)
                    ),
                    Rule.ValidateDuplicateCharacterNotInConsecutiveOrder(
                        maxTimesOfConsecutiveOrder = viewState.value.quickPinSize,
                        errorMessage = resourceProvider.getString(R.string.quick_pin_invalid_generic_error)
                    ),
                    Rule.ValidateNumericNotInConsecutiveSequenceOrder(
                        minLength = viewState.value.quickPinSize,
                        errorMessage = resourceProvider.getString(R.string.quick_pin_invalid_generic_error)
                    ),
                    Rule.ValidateNotPalindrome(
                        errorMessage = resourceProvider.getString(R.string.quick_pin_invalid_generic_error)
                    ),
                    Rule.ValidateNotCommonPin(
                        errorMessage = resourceProvider.getString(R.string.quick_pin_invalid_generic_error)
                    ),
                    Rule.ValidateNotKeyboardPattern(
                        errorMessage = resourceProvider.getString(R.string.quick_pin_invalid_generic_error)
                    )
                ) to pin
            )
        )
    }

    private fun validateForm(pin: String) {
        viewModelScope.launch {
            val validationResult = interactor.validateForm(getListOfRules(pin))
            setState {
                copy(
                    validationResult = validationResult,
                    isButtonEnabled = validationResult.isValid,
                    quickPinError = validationResult.message,
                    pin = pin,
                    resetPin = false
                )
            }
            logController.d("PIN") { "validation result: isValid=${validationResult.isValid}" }

            // FFWD to next screen if the pin is valid
            if (validationResult.isValid) {
                setEvent(Event.NextButtonPressed(pin))
            }
        }
    }

    private fun calculateSubtitle(pinState: PinValidationState): String {
        return when (pinFlow) {
            PinFlow.UPDATE -> {
                when (pinState) {
                    PinValidationState.ENTER -> resourceProvider.getString(R.string.quick_pin_change_enter_new_subtitle)
                    PinValidationState.REENTER -> resourceProvider.getString(R.string.quick_pin_change_reenter_new_subtitle)
                    PinValidationState.VALIDATE -> resourceProvider.getString(R.string.quick_pin_change_validate_current_subtitle)
                }
            }

            PinFlow.CREATE -> {
                when (pinState) {
                    PinValidationState.ENTER -> resourceProvider.getString(R.string.quick_pin_create_enter_subtitle)
                    PinValidationState.REENTER -> resourceProvider.getString(R.string.quick_pin_create_reenter_subtitle)
                    PinValidationState.VALIDATE -> viewState.value.subtitle
                }
            }
        }
    }

    private fun calculateButtonText(pinState: PinValidationState): String {
        val stringResId = when (pinState) {
            PinValidationState.ENTER -> R.string.quick_pin_next_button
            PinValidationState.REENTER -> R.string.quick_pin_confirm_button
            PinValidationState.VALIDATE -> R.string.quick_pin_next_button
        }
        return resourceProvider.getString(stringResId)
    }

    private fun getNextScreenRoute(): String {
        return when (pinFlow) {
            PinFlow.CREATE -> {
                generateComposableNavigationLink(
                    screen = BiometricSetup,
                    arguments = generateComposableArguments(emptyMap<String, String>()),
                )
            }

            PinFlow.UPDATE -> {
                generateComposableNavigationLink(
                    screen = CommonScreens.Success,
                    arguments = generateComposableArguments(
                        getArgumentsForSuccessScreen(
                            ConfigNavigation(
                                navigationType = NavigationType.PopTo(LandingScreens.Landing),
                            )
                        )
                    )
                )
            }
        }
    }

    private fun getArgumentsForSuccessScreen(navigationAfterUpdate: ConfigNavigation) = mapOf(
        SuccessUIConfig.serializedKeyName to uiSerializer.toBase64(
            getSuccessUiConfig(navigationAfterUpdate),
            SuccessUIConfig
        ).orEmpty()
    )

    private fun getSuccessUiConfig(navigationAfterUpdate: ConfigNavigation) =
        SuccessUIConfig(
            textElementsConfig = SuccessUIConfig.TextElementsConfig(
                text = resourceProvider.getString(R.string.quick_pin_change_success_text),
                description = resourceProvider.getString(R.string.quick_pin_change_success_description)
            ),
            imageConfig = SuccessUIConfig.ImageConfig(),
            buttonConfig = listOf(
                SuccessUIConfig.ButtonConfig(
                    text = resourceProvider.getString(R.string.quick_pin_change_success_btn),
                    style = SuccessUIConfig.ButtonConfig.Style.PRIMARY,
                    navigation = navigationAfterUpdate
                )
            ),
            onBackScreenToNavigate = navigationAfterUpdate,
        )

    private fun showBottomSheet() {
        setEffect {
            Effect.ShowBottomSheet
        }
    }

    private fun hideBottomSheet() {
        setEffect {
            Effect.CloseBottomSheet
        }
    }

    override fun onCleared() {
        super.onCleared()
        lockoutCountdownManager.cancel()
    }
}
