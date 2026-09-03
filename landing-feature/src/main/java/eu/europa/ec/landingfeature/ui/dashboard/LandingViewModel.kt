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

package eu.europa.ec.landingfeature.ui.dashboard

import android.net.Uri
import androidx.lifecycle.viewModelScope
import eu.europa.ec.commonfeature.config.OfferUiConfig
import eu.europa.ec.commonfeature.config.PresentationMode
import eu.europa.ec.commonfeature.config.QrScanFlow
import eu.europa.ec.commonfeature.config.QrScanUiConfig
import eu.europa.ec.commonfeature.config.RequestUriConfig
import eu.europa.ec.commonfeature.extension.toExpandableListItems
import eu.europa.ec.corelogic.di.getOrCreatePresentationScope
import eu.europa.ec.landingfeature.interactor.LandingPageInteractor
import eu.europa.ec.landingfeature.interactor.LandingPageInteractor.GetAgeCredentialPartialState
import eu.europa.ec.landingfeature.model.AgeCredentialCardUi
import eu.europa.ec.landingfeature.model.RemainingAccessesUi
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.uilogic.component.content.ContentErrorConfig
import eu.europa.ec.uilogic.component.wrap.ExpandableListItemUi
import eu.europa.ec.uilogic.config.ConfigNavigation
import eu.europa.ec.uilogic.config.NavigationType
import eu.europa.ec.uilogic.mvi.MviViewModel
import eu.europa.ec.uilogic.mvi.ViewEvent
import eu.europa.ec.uilogic.mvi.ViewSideEffect
import eu.europa.ec.uilogic.mvi.ViewState
import eu.europa.ec.uilogic.navigation.CommonScreens
import eu.europa.ec.uilogic.navigation.LandingScreens
import eu.europa.ec.uilogic.navigation.OnboardingScreens
import eu.europa.ec.uilogic.navigation.helper.DeepLinkAction
import eu.europa.ec.uilogic.navigation.helper.DeepLinkType
import eu.europa.ec.uilogic.navigation.helper.IntentAction
import eu.europa.ec.uilogic.navigation.helper.generateComposableArguments
import eu.europa.ec.uilogic.navigation.helper.generateComposableNavigationLink
import eu.europa.ec.uilogic.navigation.helper.hasDeepLink
import eu.europa.ec.uilogic.serializer.UiSerializer
import kotlinx.coroutines.launch
import org.koin.android.annotation.KoinViewModel

data class State(
    val isLoading: Boolean = false,
    val error: ContentErrorConfig? = null,
    val documentClaims: List<ExpandableListItemUi>? = null,
    val credentialCard: AgeCredentialCardUi,
) : ViewState

sealed class Event : ViewEvent {
    data class Init(val deepLinkUri: Uri?, val intentAction: IntentAction?) : Event()
    data object GoToSettings : Event()
    data object GoToScanQR : Event()
    data object Finish : Event()
    data object AddCredentials : Event()
}

sealed class Effect : ViewSideEffect {
    sealed class Navigation : Effect() {
        data class SwitchScreen(
            val screenRoute: String,
            val popUpToScreenRoute: String = LandingScreens.Landing.screenRoute,
            val inclusive: Boolean = false,
        ) : Navigation()

        data object Pop : Navigation()
        data class OpenDeepLinkAction(val deepLinkUri: Uri, val arguments: String?) : Navigation()
        data class OpenIntentAction(val intentAction: IntentAction) : Navigation()
    }
}

@KoinViewModel
class LandingViewModel(
    private val landingPageInteractor: LandingPageInteractor,
    private val resourceProvider: ResourceProvider,
    private val uiSerializer: UiSerializer,
) : MviViewModel<Event, State, Effect>() {

    override fun setInitialState(): State {
        return State(
            credentialCard = ageCredentialCard(
                ageThreshold = null,
                credentialCount = null,
            )
        )
    }

    override fun handleEvents(event: Event) {
        when (event) {
            is Event.Init -> {
                handleDeepLink(event.deepLinkUri)
                handleIntentAction(event.intentAction)
                getAgeCredential(event)
            }

            is Event.GoToSettings -> {
                switchScreen(LandingScreens.Settings.screenRoute)
            }

            is Event.GoToScanQR -> {
                navigateToQrScan()
            }

            Event.Finish -> {
                setEffect { Effect.Navigation.Pop }
            }

            Event.AddCredentials -> {
                if (viewState.value.credentialCard.remainingAccesses?.isDepleted == true) {
                    switchScreen(OnboardingScreens.Enrollment.screenRoute)
                }
            }
        }
    }

    private fun switchScreen(route: String) {
        setEffect {
            Effect.Navigation.SwitchScreen(route)
        }
    }

    private fun getAgeCredential(event: Event) {
        setState {
            copy(
                isLoading = true,
                error = null
            )
        }
        viewModelScope.launch {
            landingPageInteractor.getAgeCredential()
                .collect { result ->
                    when (result) {
                        is GetAgeCredentialPartialState.Success -> {
                            val listItems = result.ageCredentialUi.claims.map { domainClaim ->
                                domainClaim.toExpandableListItems(docId = result.ageCredentialUi.docId)
                            }
                            setState {
                                copy(
                                    isLoading = false,
                                    documentClaims = listItems,
                                    credentialCard = ageCredentialCard(
                                        ageThreshold = result.ageCredentialUi.ageThreshold,
                                        credentialCount = result.ageCredentialUi.credentialCount,
                                    ),
                                )
                            }
                        }

                        is GetAgeCredentialPartialState.Failure -> {
                            setState {
                                copy(
                                    isLoading = false,
                                    error = ContentErrorConfig(
                                        onRetry = { setEvent(event) },
                                        errorSubTitle = result.error,
                                        onCancel = { setEvent(Event.Finish) }
                                    )
                                )
                            }
                        }
                    }
                }
        }
    }

    private fun ageCredentialCard(ageThreshold: Int?, credentialCount: Int?) = AgeCredentialCardUi(
        ageThreshold = ageThreshold,
        accessibilityLabel = ageThreshold?.let {
            resourceProvider.getString(
                R.string.content_description_landing_screen_credential_card,
                it
            )
        } ?: resourceProvider.getString(
            R.string.content_description_landing_screen_credential_card_no_age
        ),
        remainingAccesses = credentialCount?.let { count -> remainingAccesses(count) },
    )

    private fun remainingAccesses(count: Int): RemainingAccessesUi = when {
        count > 0 -> RemainingAccessesUi(
            label = resourceProvider.getQuantityString(
                R.plurals.landing_screen_credentials_left,
                count,
                count
            ),
            accessibilityLabel = resourceProvider.getQuantityString(
                R.plurals.content_description_landing_screen_credentials_left,
                count,
                count
            ),
            isDepleted = false,
        )

        else -> RemainingAccessesUi(
            label = resourceProvider.getString(R.string.landing_screen_add_credentials),
            accessibilityLabel = resourceProvider.getString(
                R.string.content_description_landing_screen_add_credentials
            ),
            isDepleted = true,
        )
    }

    private fun navigateToQrScan() {
        setEffect {
            Effect.Navigation.SwitchScreen(
                screenRoute = generateComposableNavigationLink(
                    screen = CommonScreens.QrScan,
                    arguments = generateComposableArguments(
                        mapOf(
                            QrScanUiConfig.serializedKeyName to uiSerializer.toBase64(
                                QrScanUiConfig(
                                    title = resourceProvider.getString(R.string.presentation_qr_scan_title),
                                    subTitle = resourceProvider.getString(R.string.presentation_qr_scan_subtitle),
                                    qrScanFlow = QrScanFlow.Presentation
                                ),
                                QrScanUiConfig.Parser
                            )
                        )
                    )
                )
            )
        }
    }

    private fun handleDeepLink(deepLinkUri: Uri?) {
        deepLinkUri?.let { uri ->
            hasDeepLink(uri)?.let {
                val arguments: String? = when (it.type) {
                    DeepLinkType.OPENID4VP -> generatePresentationDeepLinkArguments(uri)

                    DeepLinkType.CREDENTIAL_OFFER -> generateOfferDeepLinkArguments(it)

                    else -> null
                }
                setEffect {
                    Effect.Navigation.OpenDeepLinkAction(
                        deepLinkUri = uri,
                        arguments = arguments
                    )
                }
            }
        }
    }

    private fun handleIntentAction(intentAction: IntentAction?) {
        intentAction?.let {
            getOrCreatePresentationScope()
            setEffect {
                Effect.Navigation.OpenIntentAction(it)
            }
        }
    }

    private fun generateOfferDeepLinkArguments(it: DeepLinkAction): String =
        generateComposableArguments(
            mapOf(
                OfferUiConfig.serializedKeyName to uiSerializer.toBase64(
                    OfferUiConfig(
                        offerUri = it.link.toString(),
                        onSuccessNavigation = ConfigNavigation(
                            navigationType = NavigationType.PopTo(
                                screen = LandingScreens.Landing
                            )
                        ),
                        onCancelNavigation = ConfigNavigation(
                            navigationType = NavigationType.Pop
                        )
                    ),
                    OfferUiConfig
                )
            )
        )

    private fun generatePresentationDeepLinkArguments(uri: Uri): String {
        getOrCreatePresentationScope()
        return generateComposableArguments(
            mapOf(
                RequestUriConfig.serializedKeyName to uiSerializer.toBase64(
                    RequestUriConfig(
                        PresentationMode.OpenId4Vp(
                            uri.toString(),
                            LandingScreens.Landing.screenRoute
                        )
                    ),
                    RequestUriConfig
                )
            )
        )
    }
}
