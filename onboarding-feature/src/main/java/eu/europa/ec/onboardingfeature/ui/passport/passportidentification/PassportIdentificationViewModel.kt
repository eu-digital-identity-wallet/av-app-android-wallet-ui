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
import eu.europa.ec.onboardingfeature.ui.passport.passportidentification.Effect.Navigation.GoBack
import eu.europa.ec.onboardingfeature.ui.passport.passportidentification.Effect.Navigation.StartMRZScanner
import eu.europa.ec.onboardingfeature.ui.passport.passportidentification.Effect.Navigation.StartPassportLiveCheck
import eu.europa.ec.uilogic.mvi.MviViewModel
import eu.europa.ec.uilogic.mvi.ViewEvent
import eu.europa.ec.uilogic.mvi.ViewSideEffect
import eu.europa.ec.uilogic.mvi.ViewState
import org.koin.android.annotation.KoinViewModel

data class State(
    val isLoading: Boolean = false,
) : ViewState

sealed class Event : ViewEvent {
    data object Init : Event()
    data object OnBackPressed : Event()
    data object OnStartPassportScan : Event()
    data class OnPassportScanSuccessful(val dummyData: String) : Event()
}

sealed class Effect : ViewSideEffect {
    sealed class Navigation : Effect() {
        data object GoBack : Navigation()
        data object StartMRZScanner : Navigation()
        data class StartPassportLiveCheck(val dummyData: String) : Navigation()
    }
}

@KoinViewModel
class PassportIdentificationViewModel(
    private val logController: LogController,
) : MviViewModel<Event, State, Effect>() {

    override fun setInitialState(): State = State()

    override fun handleEvents(event: Event) {
        when (event) {
            Event.Init -> logController.i { "Init -- PassportIdentificationViewModel " }
            Event.OnBackPressed -> setEffect { GoBack }
            Event.OnStartPassportScan -> setEffect { StartMRZScanner }
            // add TODO passport information as a param, which contains passport picture and birthday
            is Event.OnPassportScanSuccessful -> setEffect { StartPassportLiveCheck(event.dummyData) }
        }
    }
}
