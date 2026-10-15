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

package eu.europa.ec.commonfeature.ui.document_success

import android.net.Uri
import eu.europa.ec.businesslogic.extension.toUri
import eu.europa.ec.uilogic.component.AppIconAndTextDataUi
import eu.europa.ec.uilogic.component.content.ContentHeaderConfig
import eu.europa.ec.uilogic.component.wrap.ExpandableListItemUi
import eu.europa.ec.uilogic.config.ConfigNavigation
import eu.europa.ec.uilogic.config.NavigationType
import eu.europa.ec.uilogic.mvi.MviViewModel
import eu.europa.ec.uilogic.mvi.ViewEvent
import eu.europa.ec.uilogic.mvi.ViewSideEffect
import eu.europa.ec.uilogic.mvi.ViewState
import eu.europa.ec.uilogic.navigation.helper.generateComposableArguments
import eu.europa.ec.uilogic.navigation.helper.generateComposableNavigationLink

data class State(
    val isLoading: Boolean = false,
    val headerConfig: ContentHeaderConfig,

    val items: List<ExpandableListItemUi.NestedListItem> = emptyList(),
) : ViewState

sealed class Event : ViewEvent {
    data object DoWork : Event()
    data object StickyButtonPressed : Event()
}

sealed class Effect : ViewSideEffect {
    sealed class Navigation : Effect() {
        data class SwitchScreen(
            val screenRoute: String,
            val popUpRoute: String?,
        ) : Navigation()

        data class PopBackStackUpTo(
            val screenRoute: String,
            val inclusive: Boolean,
        ) : Navigation()

        data object Pop : Navigation()

        data class DeepLink(
            val link: Uri,
            val routeToPop: String?,
        ) : Navigation()
    }
}

abstract class DocumentSuccessViewModel : MviViewModel<Event, State, Effect>() {

    abstract fun getNextScreenConfigNavigation(): ConfigNavigation
    abstract fun doWork()

    override fun setInitialState(): State {
        return State(
            headerConfig = ContentHeaderConfig(
                appIconAndTextData = AppIconAndTextDataUi(),
                description = null,
            )
        )
    }

    override fun handleEvents(event: Event) {
        when (event) {
            is Event.DoWork -> doWork()

            is Event.StickyButtonPressed -> doNavigation(
                navigation = getNextScreenConfigNavigation()
            )
        }
    }

    private fun doNavigation(navigation: ConfigNavigation) {

        val navigationEffect: Effect.Navigation = when (val nav = navigation.navigationType) {
            is NavigationType.PopTo -> {
                Effect.Navigation.PopBackStackUpTo(
                    screenRoute = nav.screen.screenRoute,
                    inclusive = false
                )
            }

            is NavigationType.PushScreen -> {
                Effect.Navigation.SwitchScreen(
                    screenRoute = generateComposableNavigationLink(
                        screen = nav.screen,
                        arguments = generateComposableArguments(nav.arguments),
                    ),
                    popUpRoute = nav.popUpToScreen?.screenRoute
                )
            }

            is NavigationType.Deeplink -> Effect.Navigation.DeepLink(
                nav.link.toUri(),
                nav.routeToPop
            )

            is NavigationType.Pop, NavigationType.Finish -> Effect.Navigation.Pop

            is NavigationType.PushRoute -> Effect.Navigation.SwitchScreen(
                nav.route,
                nav.popUpToRoute
            )
        }

        setEffect {
            navigationEffect
        }
    }
}
