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

package eu.europa.ec.presentationfeature.ui.request

import android.app.Application
import androidx.lifecycle.viewModelScope
import eu.europa.ec.businesslogic.extension.ifEmptyOrNull
import eu.europa.ec.commonfeature.config.BiometricMode
import eu.europa.ec.commonfeature.config.BiometricUiConfig
import eu.europa.ec.commonfeature.config.OnBackNavigationConfig
import eu.europa.ec.commonfeature.config.RequestUriConfig
import eu.europa.ec.commonfeature.ui.request.Event.DoWork
import eu.europa.ec.commonfeature.ui.request.Event.Pop
import eu.europa.ec.commonfeature.ui.request.RequestViewModel
import eu.europa.ec.commonfeature.ui.request.model.RequestDocumentItemUi
import eu.europa.ec.presentationfeature.interactor.PresentationRequestInteractor
import eu.europa.ec.presentationfeature.interactor.PresentationRequestInteractorPartialState.Disconnect
import eu.europa.ec.presentationfeature.interactor.PresentationRequestInteractorPartialState.Failure
import eu.europa.ec.presentationfeature.interactor.PresentationRequestInteractorPartialState.NoData
import eu.europa.ec.presentationfeature.interactor.PresentationRequestInteractorPartialState.Success
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.uilogic.component.RelyingPartyDataUi
import eu.europa.ec.uilogic.component.content.ContentErrorConfig
import eu.europa.ec.uilogic.component.content.ContentHeaderConfig
import eu.europa.ec.uilogic.extension.createErrorConfigFromMessage
import eu.europa.ec.uilogic.config.ConfigNavigation
import eu.europa.ec.uilogic.config.NavigationType
import eu.europa.ec.uilogic.navigation.CommonScreens
import eu.europa.ec.uilogic.navigation.PresentationScreens
import eu.europa.ec.uilogic.navigation.helper.generateComposableArguments
import eu.europa.ec.uilogic.navigation.helper.generateComposableNavigationLink
import eu.europa.ec.uilogic.serializer.UiSerializer
import kotlinx.coroutines.launch
import org.koin.android.annotation.KoinViewModel
import org.koin.core.annotation.InjectedParam

@KoinViewModel
class PresentationRequestViewModel(
    private val interactor: PresentationRequestInteractor,
    private val resourceProvider: ResourceProvider,
    private val uiSerializer: UiSerializer,
    private val application: Application,
    @InjectedParam private val requestUriConfigRaw: String,
) : RequestViewModel() {

    override fun getHeaderConfig(): ContentHeaderConfig {
        return ContentHeaderConfig(
            description = resourceProvider.getString(R.string.request_header_description),
            mainText = resourceProvider.getString(R.string.request_header_main_text),
            relyingPartyData = getRelyingPartyData(
                name = null,
                isVerified = false,
            ),
        )
    }

    override fun getNextScreen(): String {
        return if (interactor.shouldUseAppAuthenticationBeforePresentation()) {
            getAppAuthenticationScreen()
        } else {
            PresentationScreens.PresentationLoading.screenRoute
        }
    }

    private fun getAppAuthenticationScreen(): String {
        return generateComposableNavigationLink(
            screen = CommonScreens.Biometric,
            arguments = generateComposableArguments(
                mapOf(
                    BiometricUiConfig.serializedKeyName to uiSerializer.toBase64(
                        BiometricUiConfig(
                            mode = BiometricMode.Default(
                                descriptionWhenBiometricsEnabled = resourceProvider.getString(R.string.loading_biometry_biometrics_enabled_description),
                                descriptionWhenBiometricsNotEnabled = resourceProvider.getString(R.string.loading_biometry_biometrics_not_enabled_description),
                                textAbovePin = resourceProvider.getString(R.string.biometric_default_mode_text_above_pin_field),
                            ),
                            isPreAuthorization = false,
                            shouldInitializeBiometricAuthOnCreate = true,
                            onSuccessNavigation = ConfigNavigation(
                                navigationType = NavigationType.PushScreen(PresentationScreens.PresentationLoading),
                            ),
                            onBackNavigationConfig = OnBackNavigationConfig(
                                onBackNavigation = ConfigNavigation(
                                    navigationType = NavigationType.PopTo(PresentationScreens.PresentationRequest),
                                ),
                                hasToolbarBackIcon = true
                            )
                        ),
                        BiometricUiConfig.Parser
                    ).orEmpty()
                )
            )
        )
    }

    override fun doWork() {
        setState {
            copy(
                isLoading = true,
                error = null
            )
        }

        val requestUriConfig = uiSerializer.fromBase64(
            requestUriConfigRaw,
            RequestUriConfig::class.java,
            RequestUriConfig.Parser
        ) ?: throw RuntimeException("RequestUriConfig:: is Missing or invalid")

        interactor.setConfig(requestUriConfig)

        viewModelJob = viewModelScope.launch {
            interactor.getRequestDocuments().collect { response ->
                when (response) {
                    is Failure -> {
                        setState {
                            copy(
                                isLoading = false,
                                error = createErrorConfigFromMessage(
                                    errorMessage = response.error,
                                    resourceProvider = resourceProvider,
                                    errorType = response.errorType,
                                    onRetry = { setEvent(DoWork) },
                                    onCancel = { setEvent(Pop) },
                                )
                            )
                        }
                    }

                    is Success -> {
                        updateData(response.requestDocuments)

                        val updatedHeaderConfig = viewState.value.headerConfig.copy(
                            relyingPartyData = getRelyingPartyData(
                                name = response.verifierName,
                                isVerified = response.verifierIsTrusted,
                            )
                        )

                        setState {
                            copy(
                                isLoading = false,
                                error = null,
                                headerConfig = updatedHeaderConfig,
                                items = response.requestDocuments,
                            )
                        }
                    }

                    is Disconnect -> {
                        setEvent(Pop)
                    }

                    is NoData -> {
                        val updatedHeaderConfig = viewState.value.headerConfig.copy(
                            relyingPartyData = getRelyingPartyData(
                                name = response.verifierName,
                                isVerified = response.verifierIsTrusted,
                            )
                        )

                        setState {
                            copy(
                                isLoading = false,
                                error = null,
                                headerConfig = updatedHeaderConfig,
                                noItems = true,
                            )
                        }
                    }
                }
            }
        }
    }

    override fun updateData(
        updatedItems: List<RequestDocumentItemUi>,
        allowShare: Boolean?,
    ) {
        super.updateData(updatedItems, allowShare)
        interactor.updateRequestedDocuments(updatedItems)
    }

    override fun cleanUp() {
        super.cleanUp()
        interactor.stopPresentation()
    }

    private fun getRelyingPartyData(
        name: String?,
        isVerified: Boolean,
    ): RelyingPartyDataUi {
        return RelyingPartyDataUi(
            isVerified = isVerified,
            name = name.ifEmptyOrNull(
                default = resourceProvider.getString(R.string.request_relying_party_default_name)
            ),
            description = resourceProvider.getString(R.string.request_relying_party_description),
        )
    }
}
