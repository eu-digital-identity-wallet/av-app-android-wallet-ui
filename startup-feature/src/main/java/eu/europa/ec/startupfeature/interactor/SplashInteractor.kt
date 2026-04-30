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

package eu.europa.ec.startupfeature.interactor

import eu.europa.ec.commonfeature.config.BiometricMode
import eu.europa.ec.commonfeature.config.BiometricUiConfig
import eu.europa.ec.commonfeature.config.OnBackNavigationConfig
import eu.europa.ec.commonfeature.interactor.QuickPinInteractor
import eu.europa.ec.corelogic.controller.WalletCoreDocumentsController
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.uilogic.config.ConfigNavigation
import eu.europa.ec.uilogic.config.NavigationType
import eu.europa.ec.uilogic.navigation.CommonScreens
import eu.europa.ec.uilogic.navigation.LandingScreens
import eu.europa.ec.uilogic.navigation.OnboardingScreens
import eu.europa.ec.uilogic.navigation.helper.generateComposableArguments
import eu.europa.ec.uilogic.navigation.helper.generateComposableNavigationLink
import eu.europa.ec.uilogic.serializer.UiSerializer

interface SplashInteractor {
    fun getAfterSplashRoute(): String
}

class SplashInteractorImpl(
    private val quickPinInteractor: QuickPinInteractor,
    private val uiSerializer: UiSerializer,
    private val resourceProvider: ResourceProvider,
    private val walletCoreDocumentsController: WalletCoreDocumentsController,
) : SplashInteractor {

    private val hasDocuments: Boolean
        get() = walletCoreDocumentsController.getAgeOver18IssuedDocument() != null

    override fun getAfterSplashRoute(): String = when (quickPinInteractor.hasPin()) {
        true -> {
            getBiometricsConfig()
        }

        false -> {
            getOnboardingRoute()
        }
    }

    private fun getOnboardingRoute(): String {
        return OnboardingScreens.Welcome.screenRoute
    }

    private fun getBiometricsConfig(): String {
        return generateComposableNavigationLink(
            screen = CommonScreens.Biometric,
            arguments = generateComposableArguments(
                mapOf(
                    BiometricUiConfig.serializedKeyName to uiSerializer.toBase64(
                        BiometricUiConfig(
                            mode = BiometricMode.Login(
                                title = resourceProvider.getString(R.string.biometric_login_title),
                                subTitleWhenBiometricsEnabled = resourceProvider.getString(R.string.biometric_login_biometrics_enabled_subtitle),
                                subTitleWhenBiometricsNotEnabled = resourceProvider.getString(R.string.biometric_login_biometrics_not_enabled_subtitle),
                            ),
                            isPreAuthorization = true,
                            shouldInitializeBiometricAuthOnCreate = true,
                            onSuccessNavigation = ConfigNavigation(
                                navigationType = NavigationType.PushScreen(
                                    screen = if (hasDocuments) {
                                        LandingScreens.Landing
                                    } else {
                                        OnboardingScreens.Enrollment
                                    },
                                    arguments = emptyMap()
                                )
                            ),
                            onBackNavigationConfig = OnBackNavigationConfig(
                                onBackNavigation = ConfigNavigation(
                                    navigationType = NavigationType.Finish
                                ),
                                hasToolbarBackIcon = false
                            )
                        ),
                        BiometricUiConfig.Parser
                    ).orEmpty()
                )
            )
        )
    }
}