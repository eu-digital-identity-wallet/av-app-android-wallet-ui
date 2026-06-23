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

package eu.europa.ec.commonfeature.router

import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.compose.navigation
import androidx.navigation.navArgument
import androidx.navigation.navDeepLink
import eu.europa.ec.commonfeature.BuildConfig
import eu.europa.ec.commonfeature.config.BiometricUiConfig
import eu.europa.ec.commonfeature.config.QrScanUiConfig
import eu.europa.ec.commonfeature.config.SuccessUIConfig
import eu.europa.ec.commonfeature.model.PinFlow
import eu.europa.ec.commonfeature.ui.biometric.BiometricScreen
import eu.europa.ec.commonfeature.ui.biometricloginsuccess.BiometricLoginSuccessScreen
import eu.europa.ec.commonfeature.ui.biometricsetup.BiometricSetupScreen
import eu.europa.ec.commonfeature.ui.pin.PinScreen
import eu.europa.ec.commonfeature.ui.qr_scan.QrScanScreen
import eu.europa.ec.commonfeature.ui.success.SuccessScreen
import eu.europa.ec.uilogic.navigation.CommonScreens
import eu.europa.ec.uilogic.navigation.CommonScreens.BiometricLoginSuccessful
import eu.europa.ec.uilogic.navigation.ModuleRoute
import org.koin.androidx.compose.koinViewModel
import org.koin.core.parameter.parametersOf

fun NavGraphBuilder.featureCommonGraph(navController: NavController) {
    navigation(
        startDestination = CommonScreens.Biometric.screenRoute,
        route = ModuleRoute.CommonModule.route
    ) {
        composable(
            route = CommonScreens.Biometric.screenRoute,
            deepLinks = listOf(
                navDeepLink {
                    uriPattern =
                        BuildConfig.DEEPLINK + CommonScreens.Biometric.screenRoute
                }
            ),
            arguments = listOf(
                navArgument(BiometricUiConfig.serializedKeyName) {
                    type = NavType.StringType
                }
            )
        ) {
            BiometricScreen(
                navController,
                koinViewModel(
                    parameters = {
                        parametersOf(
                            it.arguments?.getString(BiometricUiConfig.serializedKeyName).orEmpty()
                        )
                    }
                )
            )
        }

        composable(
            route = BiometricLoginSuccessful.screenRoute
        ) {
            BiometricLoginSuccessScreen(
                navController = navController,
                viewModel = koinViewModel(),
            )
        }

        composable(
            route = CommonScreens.Success.screenRoute,
            deepLinks = listOf(
                navDeepLink {
                    uriPattern =
                        BuildConfig.DEEPLINK + CommonScreens.Success.screenRoute
                }
            ),
            arguments = listOf(
                navArgument(SuccessUIConfig.serializedKeyName) {
                    type = NavType.StringType
                }
            )
        ) {
            SuccessScreen(
                navController,
                koinViewModel(
                    parameters = {
                        parametersOf(
                            it.arguments?.getString(SuccessUIConfig.serializedKeyName).orEmpty()
                        )
                    }
                )
            )
        }

        composable(
            route = CommonScreens.QuickPin.screenRoute,
            deepLinks = listOf(
                navDeepLink {
                    uriPattern = BuildConfig.DEEPLINK + CommonScreens.QuickPin.screenRoute
                }
            ),
            arguments = listOf(
                navArgument("pinFlow") {
                    type = NavType.StringType
                }
            )
        ) {
            PinScreen(
                navController,
                koinViewModel(
                    parameters = {
                        parametersOf(
                            PinFlow.valueOf(
                                it.arguments?.getString("pinFlow").orEmpty()
                            )
                        )
                    }
                )
            )
        }

        composable(CommonScreens.BiometricSetup.screenRoute) {
            BiometricSetupScreen(
                navController = navController,
                viewModel = koinViewModel(),
            )
        }

        composable(
            route = CommonScreens.QrScan.screenRoute,
            deepLinks = listOf(
                navDeepLink {
                    uriPattern =
                        BuildConfig.DEEPLINK + CommonScreens.QrScan.screenRoute
                }
            ),
            arguments = listOf(
                navArgument(QrScanUiConfig.serializedKeyName) {
                    type = NavType.StringType
                }
            )
        ) {
            QrScanScreen(
                navController,
                koinViewModel(
                    parameters = {
                        parametersOf(
                            it.arguments?.getString(QrScanUiConfig.serializedKeyName).orEmpty()
                        )
                    }
                )
            )
        }
    }
}
