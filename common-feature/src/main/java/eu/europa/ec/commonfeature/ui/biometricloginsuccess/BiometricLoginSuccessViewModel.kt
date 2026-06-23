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

import eu.europa.ec.commonfeature.ui.biometricloginsuccess.Effect.Navigation.SwitchScreen
import eu.europa.ec.commonfeature.ui.biometricloginsuccess.Event.Init
import eu.europa.ec.corelogic.controller.WalletCoreDocumentsController
import eu.europa.ec.uilogic.mvi.MviViewModel
import eu.europa.ec.uilogic.mvi.ViewEvent
import eu.europa.ec.uilogic.mvi.ViewSideEffect
import eu.europa.ec.uilogic.mvi.ViewState
import eu.europa.ec.uilogic.navigation.LandingScreens.Landing
import eu.europa.ec.uilogic.navigation.OnboardingScreens.Enrollment
import org.koin.android.annotation.KoinViewModel

sealed class Event : ViewEvent {
    data object Init : Event()
}

data object State : ViewState
sealed class Effect : ViewSideEffect {
    sealed class Navigation : Effect() {
        data class SwitchScreen(val screen: String) : Navigation()
    }
}

@KoinViewModel
class BiometricLoginSuccessViewModel(
    private val walletCoreDocumentsController: WalletCoreDocumentsController,
) : MviViewModel<Event, State, Effect>() {

    override fun setInitialState(): State = State

    override fun handleEvents(event: Event) {
        when (event) {
            is Init -> {
                setEffect {
                    SwitchScreen(
                        if (walletCoreDocumentsController.hasIssuedDocuments()) {
                            Landing.screenRoute
                        } else {
                            Enrollment.screenRoute
                        }
                    )
                }
            }
        }
    }
}
