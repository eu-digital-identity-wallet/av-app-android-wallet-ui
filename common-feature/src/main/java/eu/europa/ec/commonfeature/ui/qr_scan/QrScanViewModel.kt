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

package eu.europa.ec.commonfeature.ui.qr_scan

import android.content.Context
import androidx.lifecycle.viewModelScope
import eu.europa.ec.businesslogic.extension.toUri
import eu.europa.ec.businesslogic.validator.Form
import eu.europa.ec.businesslogic.validator.FormValidator
import eu.europa.ec.businesslogic.validator.Rule
import eu.europa.ec.commonfeature.config.IssuanceFlowType
import eu.europa.ec.commonfeature.config.OfferUiConfig
import eu.europa.ec.commonfeature.config.PresentationMode
import eu.europa.ec.commonfeature.config.QrScanFlow
import eu.europa.ec.commonfeature.config.QrScanUiConfig
import eu.europa.ec.commonfeature.config.RequestUriConfig
import eu.europa.ec.commonfeature.di.getOrCreateCredentialOfferScope
import eu.europa.ec.corelogic.di.getOrCreatePresentationScope
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.uilogic.config.ConfigNavigation
import eu.europa.ec.uilogic.config.NavigationType
import eu.europa.ec.uilogic.mvi.MviViewModel
import eu.europa.ec.uilogic.mvi.ViewEvent
import eu.europa.ec.uilogic.mvi.ViewSideEffect
import eu.europa.ec.uilogic.mvi.ViewState
import eu.europa.ec.uilogic.navigation.IssuanceScreens
import eu.europa.ec.uilogic.navigation.LandingScreens
import eu.europa.ec.uilogic.navigation.PresentationScreens
import eu.europa.ec.uilogic.navigation.helper.DeepLinkType
import eu.europa.ec.uilogic.navigation.helper.generateComposableArguments
import eu.europa.ec.uilogic.navigation.helper.generateComposableNavigationLink
import eu.europa.ec.uilogic.navigation.helper.hasDeepLink
import eu.europa.ec.uilogic.serializer.UiSerializer
import kotlinx.coroutines.launch
import org.koin.android.annotation.KoinViewModel
import org.koin.core.annotation.InjectedParam

private const val MAX_ALLOWED_FAILED_SCANS = 5

data class State(
    val hasCameraPermission: Boolean = false,
    val shouldShowPermissionRational: Boolean = false,
    val finishedScanning: Boolean = false,
    val qrScannedConfig: QrScanUiConfig,

    val failedScanAttempts: Int = 0,
    val showInformativeText: Boolean = false,
    val informativeText: String,
) : ViewState

sealed class Event : ViewEvent {
    data object GoBack : Event()
    data class OnQrScanned(val context: Context, val resultQr: String) : Event()
    data object CameraAccessGranted : Event()
    data object ShowPermissionRational : Event()
    data object GoToAppSettings : Event()
}

sealed class Effect : ViewSideEffect {
    sealed class Navigation : Effect() {
        data class SwitchScreen(val screenRoute: String) : Navigation()
        data object Pop : Navigation()
        data object GoToAppSettings : Navigation()
        data class OpenExternalUrl(val url: String) : Navigation()
    }
}

@KoinViewModel
class QrScanViewModel(
    private val formValidator: FormValidator,
    private val uiSerializer: UiSerializer,
    private val resourceProvider: ResourceProvider,
    @InjectedParam private val qrScannedConfig: String,
) : MviViewModel<Event, State, Effect>() {

    override fun setInitialState(): State {
        val deserializedConfig: QrScanUiConfig = uiSerializer.fromBase64(
            qrScannedConfig,
            QrScanUiConfig::class.java,
            QrScanUiConfig.Parser
        ) ?: throw RuntimeException("QrScanUiConfig:: is Missing or invalid")
        return State(
            qrScannedConfig = deserializedConfig,
            informativeText = calculateInformativeText(deserializedConfig.qrScanFlow)
        )
    }

    override fun handleEvents(event: Event) {
        when (event) {
            is Event.GoBack -> setEffect { Effect.Navigation.Pop }

            is Event.OnQrScanned -> {
                if (viewState.value.finishedScanning) {
                    return
                }
                setState {
                    copy(finishedScanning = true)
                }

                handleScannedQr(scannedQr = event.resultQr)
            }

            is Event.CameraAccessGranted -> {
                setState {
                    copy(hasCameraPermission = true)
                }
            }

            is Event.ShowPermissionRational -> {
                setState {
                    copy(shouldShowPermissionRational = true)
                }
            }

            is Event.GoToAppSettings -> setEffect { Effect.Navigation.GoToAppSettings }
        }
    }

    private fun handleScannedQr(scannedQr: String) {
        viewModelScope.launch {
            val currentState = viewState.value

            // Validate the scanned QR code
            val urlIsValid = validateForm(
                form = Form(
                    inputs = mapOf(
                        listOf(
                            Rule.ValidateUrl(
                                errorMessage = "",
                                shouldValidateSchema = true,
                                shouldValidateHost = false,
                                shouldValidatePath = false,
                                shouldValidateQuery = false, // allows DC API(FIDO) links without query
                            )
                        ) to scannedQr
                    )
                )
            )

            // Handle valid QR code
            if (urlIsValid) {
                calculateNextStep(
                    qrScanFlow = currentState.qrScannedConfig.qrScanFlow,
                    scanResult = scannedQr
                )
            } else {
                onScanFailed()
            }
        }
    }

    private fun onScanFailed() {
        // Increment failed attempts
        val updatedFailedAttempts = viewState.value.failedScanAttempts + 1
        val maxFailedAttemptsExceeded = updatedFailedAttempts > MAX_ALLOWED_FAILED_SCANS

        setState {
            copy(
                failedScanAttempts = updatedFailedAttempts,
                showInformativeText = maxFailedAttemptsExceeded,
                finishedScanning = false,
            )
        }
    }

    private suspend fun validateForm(form: Form): Boolean {
        val validationResult = formValidator.validateForm(
            form = form,
        )
        return validationResult.isValid
    }

    private fun calculateNextStep(
        qrScanFlow: QrScanFlow,
        scanResult: String,
    ) {
        when (qrScanFlow) {
            is QrScanFlow.Presentation -> when {
                scanResult.isCredentialOffer() -> navigateToDocumentOffer(
                    scanResult = scanResult,
                    issuanceFlowType = IssuanceFlowType.ExtraDocument(formatType = null)
                )

                // An offer scheme that DeepLinkHelper rejected, e.g. on an unknown host
                scanResult.hasCredentialOfferScheme() -> onScanFailed()

                else -> navigateToPresentationRequest(scanResult)
            }

            is QrScanFlow.Issuance -> navigateToDocumentOffer(
                scanResult = scanResult,
                issuanceFlowType = qrScanFlow.issuanceFlowType
            )
        }
    }

    private fun String.isCredentialOffer(): Boolean =
        hasDeepLink(toUri())?.type == DeepLinkType.CREDENTIAL_OFFER

    private fun String.hasCredentialOfferScheme(): Boolean =
        toUri().scheme?.let { DeepLinkType.parse(it) } == DeepLinkType.CREDENTIAL_OFFER

    private fun calculateInformativeText(
        qrScanFlow: QrScanFlow,
    ): String {
        return with(resourceProvider) {
            when (qrScanFlow) {
                is QrScanFlow.Presentation -> getString(R.string.qr_scan_informative_text_presentation_flow)
                is QrScanFlow.Issuance -> getString(R.string.qr_scan_informative_text_issuance_flow)
            }
        }
    }

    private fun navigateToPresentationRequest(scanResult: String) {
        val isDcApiQr = scanResult.startsWith("FIDO:", ignoreCase = true)
        if (isDcApiQr) {
            setEffect {
                Effect.Navigation.OpenExternalUrl(scanResult)
            }
        } else {
            setEffect {
                getOrCreatePresentationScope()
                Effect.Navigation.SwitchScreen(
                    screenRoute = generateComposableNavigationLink(
                        screen = PresentationScreens.PresentationRequest,
                        arguments = generateComposableArguments(
                            mapOf(
                                RequestUriConfig.serializedKeyName to uiSerializer.toBase64(
                                    RequestUriConfig(
                                        PresentationMode.OpenId4Vp(
                                            uri = scanResult,
                                            initiatorRoute = LandingScreens.Landing.screenRoute
                                        )
                                    ),
                                    RequestUriConfig.Parser
                                )
                            )
                        )
                    )
                )
            }
        }
    }

    private fun navigateToDocumentOffer(scanResult: String, issuanceFlowType: IssuanceFlowType) {
        getOrCreateCredentialOfferScope()
        setEffect {
            Effect.Navigation.SwitchScreen(
                screenRoute = generateComposableNavigationLink(
                    screen = IssuanceScreens.DocumentOffer,
                    arguments = generateComposableArguments(
                        mapOf(
                            OfferUiConfig.serializedKeyName to uiSerializer.toBase64(
                                OfferUiConfig(
                                    offerUri = scanResult,
                                    onSuccessNavigation = calculateOnSuccessNavigation(
                                        issuanceFlowType
                                    ),
                                    onCancelNavigation = calculateOnCancelNavigation(
                                        issuanceFlowType
                                    )
                                ),
                                OfferUiConfig.Parser
                            )
                        )
                    )
                )
            )
        }
    }

    private fun calculateOnSuccessNavigation(issuanceFlowType: IssuanceFlowType): ConfigNavigation {
        return when (issuanceFlowType) {
            is IssuanceFlowType.NoDocument -> {
                ConfigNavigation(
                    navigationType = NavigationType.PushRoute(
                        route = LandingScreens.Landing.screenRoute,
                        popUpToRoute = IssuanceScreens.AddDocument.screenRoute
                    )
                )
            }

            is IssuanceFlowType.ExtraDocument -> {
                ConfigNavigation(
                    navigationType = NavigationType.PopTo(
                        screen = LandingScreens.Landing
                    )
                )
            }
        }
    }

    private fun calculateOnCancelNavigation(issuanceFlowType: IssuanceFlowType): ConfigNavigation {
        return when (issuanceFlowType) {
            is IssuanceFlowType.NoDocument -> {
                ConfigNavigation(
                    navigationType = NavigationType.Pop
                )
            }

            is IssuanceFlowType.ExtraDocument -> {
                ConfigNavigation(
                    navigationType = NavigationType.PopTo(
                        screen = LandingScreens.Landing
                    )
                )
            }
        }
    }
}