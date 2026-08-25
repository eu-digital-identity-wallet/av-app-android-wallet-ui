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

package eu.europa.ec.onboardingfeature.ui.enrollment

import android.content.Context
import android.net.Uri
import androidx.lifecycle.viewModelScope
import eu.europa.ec.commonfeature.config.IssuanceSuccessUiConfig
import eu.europa.ec.commonfeature.config.OfferUiConfig
import eu.europa.ec.commonfeature.config.PresentationMode
import eu.europa.ec.commonfeature.config.RequestUriConfig
import eu.europa.ec.corelogic.di.getOrCreatePresentationScope
import eu.europa.ec.onboardingfeature.interactor.EnrollmentInteractor
import eu.europa.ec.onboardingfeature.interactor.EnrollmentInteractorPartialState
import eu.europa.ec.onboardingfeature.ui.enrollment.model.EnrollmentMethodUi
import eu.europa.ec.onboardingfeature.ui.enrollment.model.toUi
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.uilogic.component.content.ContentErrorConfig
import eu.europa.ec.uilogic.config.ConfigNavigation
import eu.europa.ec.uilogic.config.NavigationType
import eu.europa.ec.uilogic.extension.createErrorConfigFromMessage
import eu.europa.ec.uilogic.mvi.MviViewModel
import eu.europa.ec.uilogic.mvi.ViewEvent
import eu.europa.ec.uilogic.mvi.ViewSideEffect
import eu.europa.ec.uilogic.mvi.ViewState
import eu.europa.ec.uilogic.navigation.IssuanceScreens
import eu.europa.ec.uilogic.navigation.LandingScreens
import eu.europa.ec.uilogic.navigation.OnboardingScreens
import eu.europa.ec.uilogic.navigation.PresentationScreens
import eu.europa.ec.uilogic.navigation.helper.DeepLinkType
import eu.europa.ec.uilogic.navigation.helper.generateComposableArguments
import eu.europa.ec.uilogic.navigation.helper.generateComposableNavigationLink
import eu.europa.ec.uilogic.navigation.helper.hasDeepLink
import eu.europa.ec.uilogic.serializer.UiSerializer
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import org.koin.android.annotation.KoinViewModel

data class State(
    val isLoading: Boolean = false,
    val error: ContentErrorConfig? = null,
    val isOnboarding: Boolean = true,
    val availableEnrollmentMethods: List<EnrollmentMethodUi> = emptyList(),
) : ViewState

sealed class Event : ViewEvent {
    data class Init(val deepLink: Uri?) : Event()
    data object Pop : Event()
    data class SelectEnrollmentMethod(val method: EnrollmentMethod, val context: Context) : Event()
    data object OnPause : Event()
    data class OnResumeIssuance(val uri: String) : Event()
    data class OnDynamicPresentation(val uri: String) : Event()
    data object DismissError : Event()
}

sealed class Effect : ViewSideEffect {
    sealed class Navigation : Effect() {
        data object Finish : Navigation()
        data class SwitchScreen(val screenRoute: String, val inclusive: Boolean) : Navigation()
        data class OpenDeepLinkAction(val deepLinkUri: Uri, val arguments: String?) : Navigation()
    }
}

enum class EnrollmentMethod {
    NATIONAL_ID,
    PASSPORT_ID_CARD,
    TOKEN_QR,
}

@KoinViewModel
class EnrollmentViewModel(
    private val resourceProvider: ResourceProvider,
    private val uiSerializer: UiSerializer,
    private val enrollmentInteractor: EnrollmentInteractor,
) : MviViewModel<Event, State, Effect>() {

    private var issuanceJob: Job? = null

    override fun setInitialState(): State {
        val isOnboarding = !enrollmentInteractor.hasDocuments()
        val availableMethods = buildList {
            add(EnrollmentMethod.NATIONAL_ID)
            if (enrollmentInteractor.isPassportScanningAvailable()) {
                add(EnrollmentMethod.PASSPORT_ID_CARD)
            }
            if (isOnboarding) {
                add(EnrollmentMethod.TOKEN_QR)
            }
        }

        return State(
            isOnboarding = isOnboarding,
            availableEnrollmentMethods = availableMethods.map { it.toUi() }
        )
    }

    override fun handleEvents(event: Event) {
        when (event) {
            is Event.Init -> {
                handleDeepLink(event.deepLink)
            }

            is Event.DismissError -> {
                setState { copy(error = null) }
            }

            is Event.SelectEnrollmentMethod -> {
                when (event.method) {
                    EnrollmentMethod.NATIONAL_ID -> {
                        issueNationalEID(event.context)
                    }

                    EnrollmentMethod.PASSPORT_ID_CARD -> {
                        navigateToPassportScanIntro()
                    }

                    EnrollmentMethod.TOKEN_QR -> {
                        navigateToTokenQrIntro()
                    }
                }
            }

            is Event.OnPause -> {
                setState { copy(isLoading = false) }
            }

            is Event.OnResumeIssuance -> {
                setState {
                    copy(isLoading = true)
                }
                enrollmentInteractor.resumeOpenId4VciWithAuthorization(event.uri)
            }

            is Event.OnDynamicPresentation -> {
                handleDynamicPresentation(event.uri)
            }

            Event.Pop -> {
                if (!viewState.value.isOnboarding) {
                    setEffect {
                        Effect.Navigation.SwitchScreen(
                            LandingScreens.Landing.screenRoute,
                            inclusive = true
                        )
                    }
                } else {
                    setEffect { Effect.Navigation.Finish }
                }
            }
        }
    }

    private fun handleDynamicPresentation(uri: String) {
        getOrCreatePresentationScope()
        setEffect {
            Effect.Navigation.SwitchScreen(
                generateComposableNavigationLink(
                    PresentationScreens.PresentationRequest,
                    generateComposableArguments(
                        mapOf(
                            RequestUriConfig.serializedKeyName to uiSerializer.toBase64(
                                RequestUriConfig(
                                    PresentationMode.OpenId4Vp(
                                        uri,
                                        IssuanceScreens.AddDocument.screenRoute
                                    )
                                ),
                                RequestUriConfig
                            )
                        )
                    )
                ),
                inclusive = false
            )
        }
    }

    private fun issueNationalEID(context: Context) {
        issuanceJob?.cancel()
        issuanceJob = viewModelScope.launch {

            setState { copy(isLoading = true, error = null) }

            enrollmentInteractor.issueNationalEID(context).collect { state ->
                when (state) {
                    is EnrollmentInteractorPartialState.Success -> {
                        setState { copy(isLoading = false) }
                        navigateToSuccessScreen(state.documentId)
                    }

                    is EnrollmentInteractorPartialState.DeferredSuccess -> {
                        setState { copy(isLoading = false) }
                        navigateToDeferredSuccessScreen(state.successRoute)
                    }

                    is EnrollmentInteractorPartialState.UserAuthRequired -> {
                        enrollmentInteractor.handleUserAuth(
                            context = context,
                            crypto = state.crypto,
                            notifyOnAuthenticationFailure = true,
                            resultHandler = state.resultHandler
                        )
                    }

                    is EnrollmentInteractorPartialState.Failure -> {
                        setState {
                            copy(
                                isLoading = false,
                                error = createErrorConfigFromMessage(
                                    errorMessage = state.error,
                                    resourceProvider = resourceProvider,
                                    errorType = state.errorType,
                                    onRetry = {
                                        setEvent(
                                            Event.SelectEnrollmentMethod(
                                                EnrollmentMethod.NATIONAL_ID,
                                                context
                                            )
                                        )
                                    },
                                    onCancel = {
                                        setEvent(Event.DismissError)
                                        if (!viewState.value.isOnboarding) {
                                            setEvent(Event.Pop)
                                        }
                                    }
                                )
                            )
                        }
                    }
                }
            }
        }
    }

    private fun navigateToSuccessScreen(documentId: String) {
        val onSuccessNavigation = ConfigNavigation(
            navigationType = NavigationType.PushScreen(
                screen = LandingScreens.Landing,
                popUpToScreen = OnboardingScreens.Enrollment
            )
        )

        setEffect {
            Effect.Navigation.SwitchScreen(
                screenRoute = generateComposableNavigationLink(
                    screen = IssuanceScreens.DocumentIssuanceSuccess,
                    arguments = generateComposableArguments(
                        mapOf(
                            IssuanceSuccessUiConfig.serializedKeyName to uiSerializer.toBase64(
                                model = IssuanceSuccessUiConfig(
                                    documentIds = listOf(documentId),
                                    onSuccessNavigation = onSuccessNavigation,
                                ),
                                parser = IssuanceSuccessUiConfig.Parser
                            ).orEmpty()
                        )
                    )
                ),
                inclusive = false
            )
        }
    }

    private fun navigateToDeferredSuccessScreen(route: String) {
        setEffect {
            Effect.Navigation.SwitchScreen(
                screenRoute = route,
                inclusive = true
            )
        }
    }

    private fun navigateToPassportScanIntro() {
        setEffect {
            Effect.Navigation.SwitchScreen(
                screenRoute = OnboardingScreens.DocumentScanIntro.screenRoute,
                inclusive = false
            )
        }
    }

    private fun navigateToTokenQrIntro() {
        setEffect {
            Effect.Navigation.SwitchScreen(
                screenRoute = OnboardingScreens.TokenQrIntro.screenRoute,
                inclusive = false
            )
        }
    }

    private fun handleDeepLink(deepLinkUri: Uri?) {
        deepLinkUri?.let { uri ->
            hasDeepLink(uri)?.let {
                when (it.type) {
                    DeepLinkType.CREDENTIAL_OFFER -> {
                        setEffect {
                            Effect.Navigation.OpenDeepLinkAction(
                                deepLinkUri = uri,
                                arguments = generateComposableArguments(
                                    mapOf(
                                        OfferUiConfig.serializedKeyName to uiSerializer.toBase64(
                                            OfferUiConfig(
                                                offerUri = it.link.toString(),
                                                onSuccessNavigation = ConfigNavigation(
                                                    navigationType = NavigationType.PushScreen(
                                                        screen = LandingScreens.Landing,
                                                        popUpToScreen = IssuanceScreens.AddDocument
                                                    )
                                                ),
                                                onCancelNavigation = ConfigNavigation(
                                                    navigationType = NavigationType.Pop
                                                )
                                            ),
                                            OfferUiConfig.Parser
                                        )
                                    )
                                )
                            )
                        }
                    }

                    DeepLinkType.EXTERNAL -> {
                        setEffect {
                            Effect.Navigation.OpenDeepLinkAction(
                                deepLinkUri = uri,
                                arguments = null
                            )
                        }
                    }

                    else -> {}
                }
            }
        }
    }
}
