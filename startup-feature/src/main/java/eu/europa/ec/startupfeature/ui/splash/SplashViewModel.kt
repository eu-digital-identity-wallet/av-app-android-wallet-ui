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

package eu.europa.ec.startupfeature.ui.splash

import androidx.lifecycle.viewModelScope
import eu.europa.ec.startupfeature.interactor.SplashInteractor
import eu.europa.ec.uilogic.mvi.MviViewModel
import eu.europa.ec.uilogic.mvi.ViewEvent
import eu.europa.ec.uilogic.mvi.ViewSideEffect
import eu.europa.ec.uilogic.mvi.ViewState
import eu.europa.ec.uilogic.navigation.ModuleRoute
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.koin.android.annotation.KoinViewModel
import kotlin.time.Duration.Companion.milliseconds

data class State(
    val placeholder: Unit = Unit
) : ViewState

sealed class Event : ViewEvent {
    data object Initialize : Event()
}

sealed class Effect : ViewSideEffect {

    sealed class Navigation : Effect() {
        data class SwitchModule(val moduleRoute: ModuleRoute) : Navigation()
        data class SwitchScreen(val route: String) : Navigation()
    }
}

@KoinViewModel
class SplashViewModel(
    private val interactor: SplashInteractor,
) : MviViewModel<Event, State, Effect>() {
    override fun setInitialState() = State()
    override fun handleEvents(event: Event) {
        when (event) {
            Event.Initialize -> enterApplication()
        }
    }

    private fun enterApplication() {
        viewModelScope.launch {
            delay(500.milliseconds)
            val screenRoute = interactor.getAfterSplashRoute()
            setEffect {
                Effect.Navigation.SwitchScreen(screenRoute)
            }
        }
    }
}
