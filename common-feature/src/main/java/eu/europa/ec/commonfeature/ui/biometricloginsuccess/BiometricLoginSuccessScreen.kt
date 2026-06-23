/*
 * Copyright (c) 2026 European Commission
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

package eu.europa.ec.commonfeature.ui.biometricloginsuccess

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.navigation.NavController
import eu.europa.ec.commonfeature.ui.biometricloginsuccess.Effect.Navigation.SwitchScreen
import eu.europa.ec.commonfeature.ui.biometricloginsuccess.Event.Init
import eu.europa.ec.uilogic.navigation.CommonScreens.BiometricLoginSuccessful
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.onEach

@Composable
fun BiometricLoginSuccessScreen(navController: NavController, viewModel: BiometricLoginSuccessViewModel) {
    LaunchedEffect(Unit) {
        viewModel.setEvent(Init)
    }

    LaunchedEffect(Unit) {
        viewModel.effect.onEach { effect ->
            when (effect) {
                is SwitchScreen -> {
                    navController.navigate(effect.screen) {
                        popUpTo(BiometricLoginSuccessful.screenRoute) { inclusive = true }
                    }
                }
            }
        }.collect()
    }
}
