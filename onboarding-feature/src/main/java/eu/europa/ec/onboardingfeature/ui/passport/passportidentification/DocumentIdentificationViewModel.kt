/*
 * Copyright (c) 2023 European Commission
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

package eu.europa.ec.onboardingfeature.ui.passport.passportidentification

import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.onboardingfeature.config.PassportLiveVideoUiConfig
import eu.europa.ec.onboardingfeature.interactor.DocumentIdentificationInteractor
import eu.europa.ec.onboardingfeature.interactor.DocumentValidationState
import eu.europa.ec.onboardingfeature.session.PassportOnboardingSession
import eu.europa.ec.onboardingfeature.ui.passport.passportidentification.Effect.Navigation.GoBack
import eu.europa.ec.onboardingfeature.ui.passport.passportidentification.Effect.Navigation.StartMRZScanner
import eu.europa.ec.onboardingfeature.ui.passport.passportidentification.Effect.Navigation.SwitchScreen
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.uilogic.component.content.ContentErrorConfig
import eu.europa.ec.uilogic.mvi.MviViewModel
import eu.europa.ec.uilogic.mvi.ViewEvent
import eu.europa.ec.uilogic.mvi.ViewSideEffect
import eu.europa.ec.uilogic.mvi.ViewState
import eu.europa.ec.uilogic.navigation.OnboardingScreens
import eu.europa.ec.uilogic.navigation.helper.generateComposableArguments
import eu.europa.ec.uilogic.navigation.helper.generateComposableNavigationLink
import eu.europa.ec.uilogic.serializer.UiSerializer
import org.koin.android.annotation.KoinViewModel
import java.util.UUID

sealed class DocumentErrors(val errorMessage: Int) {
    data object NoDocumentDataReceived : DocumentErrors(R.string.passport_biometrics_no_passport_data)
    data object ScanCancelled : DocumentErrors(R.string.passport_biometrics_scan_cancelled)
    data object UnknownError: DocumentErrors(R.string.passport_biometrics_unknown_error)
}

data class State(
    val isLoading: Boolean = false,
    val scanComplete: Boolean = false,
    val scannedDocument: ScannedDocument? = null,
    val error: ContentErrorConfig? = null,
    val activeSessionId: String? = null,
) : ViewState

sealed class Event : ViewEvent {
    data object OnBackPressed : Event()
    data object OnStartPassportScan : Event()
    data object OnProcessRestartRequest : Event()
    data object OnPassportVerificationCompletion : Event()
    data class OnDocumentScanSuccessful(val scannedDocument: ScannedDocument) : Event()
    data class OnDocumentScanFailed(var errors: DocumentErrors) : Event()
    data object OnRetry : Event()
}

sealed class Effect : ViewSideEffect {
    sealed class Navigation : Effect() {
        data object GoBack : Navigation()
        data object StartMRZScanner : Navigation()
        data class SwitchScreen(val screenRoute: String) : Navigation()
    }
}

@KoinViewModel
class DocumentIdentificationViewModel(
    private val logController: LogController,
    private val uiSerializer: UiSerializer,
    private val documentIdentificationInteractor: DocumentIdentificationInteractor,
    private val resourceProvider: ResourceProvider,
    private val passportOnboardingSession: PassportOnboardingSession,
) : MviViewModel<Event, State, Effect>() {

    override fun setInitialState(): State = State()

    override fun handleEvents(event: Event) {
        when (event) {
            Event.OnBackPressed -> setEffect { GoBack }
            Event.OnStartPassportScan -> setEffect { StartMRZScanner }
            Event.OnPassportVerificationCompletion -> handlePassportVerification()
            Event.OnProcessRestartRequest -> setEffect { GoBack }
            is Event.OnDocumentScanSuccessful -> setState {
                copy(
                    scanComplete = true,
                    scannedDocument = event.scannedDocument
                )
            }

            is Event.OnDocumentScanFailed -> {
                logController.e { "Document scan failed: ${resourceProvider.getString(event.errors.errorMessage)}" }
                setState { copy(scanComplete = false, scannedDocument = null) }
            }

            Event.OnRetry -> setState { copy(error = null) }
        }
    }

    private fun handlePassportVerification() {
        val scannedDocument = viewState.value.scannedDocument
        if (scannedDocument == null ||
            scannedDocument.dateOfBirth.isNullOrEmpty() ||
            scannedDocument.expiryDate.isNullOrEmpty() ||
            (scannedDocument is ScannedDocument.Passport && scannedDocument.faceImage == null)
        ) {
            logController.e { "Document data is incomplete, cannot verify" }
            showError(resourceProvider.getString(R.string.passport_validation_error_incomplete_data))
            return
        }

        setState { copy(isLoading = true, error = null) }

        when (val validationResult = documentIdentificationInteractor.validateDocument(
            dateOfBirth = scannedDocument.dateOfBirth!!,
            expiryDate = scannedDocument.expiryDate!!
        )) {
            is DocumentValidationState.Success -> {
                logController.i { "Document validation successful, navigating to live video" }
                setState { copy(isLoading = false) }
                val link: Effect.Navigation = if (scannedDocument is ScannedDocument.Passport) {
                    generatePasswordLiveLink(scannedDocument)
                } else {
                    // todo go to issuance flow for eid
                    generateCredentialIssuanceScreenLink()
                }
                setEffect { link }
            }

            is DocumentValidationState.Failure -> {
                logController.e { "Document validation failed: ${validationResult.error}" }
                setState { copy(isLoading = false) }
                showError(validationResult.error)
            }
        }
    }

    private fun generateCredentialIssuanceScreenLink(): Effect.Navigation {
        return SwitchScreen(OnboardingScreens.IdentityDocumentCredentialIssuance.screenRoute)
    }

    private fun generatePasswordLiveLink(passport: ScannedDocument.Passport): SwitchScreen {
        val faceImage = requireNotNull(passport.faceImage) {
            "faceImage must not be null — caller already validated it in handlePassportVerification"
        }
        val sessionId = UUID.randomUUID().toString()
        passportOnboardingSession.put(sessionId, faceImage)
        val previousSessionId = viewState.value.activeSessionId
        if (previousSessionId != null) {
            passportOnboardingSession.remove(previousSessionId)
        }
        setState { copy(activeSessionId = sessionId) }
        return SwitchScreen(
            generateComposableNavigationLink(
                OnboardingScreens.PassportLiveVideo,
                generateComposableArguments(
                    mapOf(
                        PassportLiveVideoUiConfig.serializedKeyName to uiSerializer.toBase64(
                            PassportLiveVideoUiConfig(
                                dateOfBirth = passport.dateOfBirth!!,
                                expiryDate = passport.expiryDate!!,
                                sessionId = sessionId,
                            ),
                            PassportLiveVideoUiConfig.Parser
                        )
                    )
                )
            )
        )
    }

    override fun onCleared() {
        super.onCleared()
        viewState.value.activeSessionId?.let { passportOnboardingSession.remove(it) }
    }

    private fun showError(errorMessage: String) {
        setState {
            copy(
                error = ContentErrorConfig(
                    errorSubTitle = errorMessage,
                    onCancel = { setEvent(Event.OnBackPressed) },
                    onRetry = { setEvent(Event.OnRetry) }
                )
            )
        }
    }
}
