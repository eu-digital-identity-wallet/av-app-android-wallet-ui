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

package eu.europa.ec.commonfeature.ui.success

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import eu.europa.ec.commonfeature.config.SuccessUIConfig
import eu.europa.ec.commonfeature.util.TestTag
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.theme.values.ThemeColors
import eu.europa.ec.resourceslogic.theme.values.success
import eu.europa.ec.uilogic.component.AppIcons
import eu.europa.ec.uilogic.component.content.ContentHeader
import eu.europa.ec.uilogic.component.content.ContentScreen
import eu.europa.ec.uilogic.component.content.ScreenNavigateAction
import eu.europa.ec.uilogic.component.content.ScrollableFullHeightColumn
import eu.europa.ec.uilogic.component.preview.PreviewTheme
import eu.europa.ec.uilogic.component.preview.ThemeModePreviews
import eu.europa.ec.uilogic.component.utils.PERCENTAGE_25
import eu.europa.ec.uilogic.component.utils.SIZE_MEDIUM
import eu.europa.ec.uilogic.component.utils.SPACING_SMALL
import eu.europa.ec.uilogic.component.utils.screenHeightInDp
import eu.europa.ec.uilogic.component.wrap.ButtonConfig
import eu.europa.ec.uilogic.component.wrap.ButtonType
import eu.europa.ec.uilogic.component.wrap.WrapButton
import eu.europa.ec.uilogic.component.wrap.WrapImage
import eu.europa.ec.uilogic.config.ConfigNavigation
import eu.europa.ec.uilogic.config.NavigationType
import eu.europa.ec.uilogic.extension.cacheDeepLink
import eu.europa.ec.uilogic.navigation.StartupScreens
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
fun SuccessScreen(
    navController: NavController,
    viewModel: SuccessViewModel
) {
    val context = LocalContext.current
    val state: State by viewModel.viewState.collectAsStateWithLifecycle()

    ContentScreen(
        isLoading = false,
        onBack = { viewModel.setEvent(Event.BackPressed) },
        navigatableAction = ScreenNavigateAction.NONE
    ) { paddingValues ->
        SuccessScreenView(
            state = state,
            effectFlow = viewModel.effect,
            onEventSent = { event -> viewModel.setEvent(event) },
            onNavigationRequested = { navigationEffect ->
                when (navigationEffect) {
                    is Effect.Navigation.SwitchScreen -> {
                        navController.navigate(navigationEffect.screenRoute) {
                            navigationEffect.popUpRoute?.let { popUpToRoute ->
                                popUpTo(popUpToRoute) {
                                    inclusive = true
                                }
                            }
                        }
                    }

                    is Effect.Navigation.PopBackStackUpTo -> {
                        navController.popBackStack(
                            route = navigationEffect.screenRoute,
                            inclusive = navigationEffect.inclusive
                        )
                    }

                    is Effect.Navigation.DeepLink -> {
                        context.cacheDeepLink(navigationEffect.link)
                        navigationEffect.routeToPop?.let {
                            navController.popBackStack(
                                route = it,
                                inclusive = false
                            )
                        } ?: navController.popBackStack()
                    }

                    is Effect.Navigation.Pop -> navController.popBackStack()
                }
            },
            paddingValues = paddingValues
        )
    }
}

@Composable
private fun SuccessScreenView(
    state: State,
    effectFlow: Flow<Effect>,
    onEventSent: (Event) -> Unit,
    onNavigationRequested: (Effect.Navigation) -> Unit,
    paddingValues: PaddingValues
) {
    ScrollableFullHeightColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(paddingValues),
        verticalArrangement = Arrangement.SpaceBetween,
    ) {
        ContentHeader(
            modifier = Modifier.fillMaxWidth(),
            config = state.successConfig.headerConfig,
        )

        val imageConfig = state.successConfig.imageConfig
        // Bounded by the viewport height too, so landscape does not hand it the long screen edge.
        val imageModifier = Modifier
            .fillMaxWidth(imageConfig.screenPercentageSize)
            .heightIn(max = screenHeightInDp(true) * imageConfig.screenPercentageSize)
        Column(
            modifier = Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            when (imageConfig.type) {
                is SuccessUIConfig.ImageConfig.Type.Default -> WrapImage(
                    modifier = imageModifier,
                    iconData = AppIcons.Success,
                    colorFilter = ColorFilter.tint(MaterialTheme.colorScheme.success),
                    contentScale = ContentScale.Fit
                )

                is SuccessUIConfig.ImageConfig.Type.Drawable -> WrapImage(
                    modifier = imageModifier,
                    iconData = imageConfig.type.icon,
                    colorFilter = imageConfig.tint?.let { safeImageColorTint ->
                        ColorFilter.tint(safeImageColorTint)
                    },
                    contentScale = ContentScale.Fit
                )
            }

            Text(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = SPACING_SMALL.dp),
                text = state.successConfig.textElementsConfig.text,
                style = MaterialTheme.typography.headlineLarge.copy(
                    color = state.successConfig.textElementsConfig.color
                ),
                textAlign = TextAlign.Center,
            )

            Text(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = SPACING_SMALL.dp),
                text = state.successConfig.textElementsConfig.description,
                style = MaterialTheme.typography.bodyLarge.copy(
                    color = MaterialTheme.colorScheme.onSurface
                ),
                textAlign = TextAlign.Center,
            )
        }

        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            state.successConfig.buttonConfig.forEach { buttonConfig ->
                Button(
                    onEventSent = onEventSent,
                    config = buttonConfig
                )
            }
        }
    }

    LaunchedEffect(Unit) {
        effectFlow.onEach { effect ->
            when (effect) {
                is Effect.Navigation -> onNavigationRequested(effect)
            }
        }.collect()
    }
}

@Composable
private fun Button(
    onEventSent: (Event) -> Unit,
    config: SuccessUIConfig.ButtonConfig
) {
    when (config.style) {
        SuccessUIConfig.ButtonConfig.Style.PRIMARY -> {
            WrapButton(
                buttonConfig = ButtonConfig(
                    type = ButtonType.PRIMARY,
                    onClick = { onEventSent(Event.ButtonClicked(config)) },
                ),
                modifier = Modifier
                    .testTag(TestTag.SuccessScreen.PRIMARY_BUTTON)
                    .fillMaxWidth(),
            ) {
                ButtonRow(text = config.text)
            }
        }

        SuccessUIConfig.ButtonConfig.Style.OUTLINE -> {
            WrapButton(
                buttonConfig = ButtonConfig(
                    type = ButtonType.SECONDARY,
                    onClick = { onEventSent(Event.ButtonClicked(config)) },
                ),
                modifier = Modifier
                    .testTag(TestTag.SuccessScreen.SECONDARY_BUTTON)
                    .fillMaxWidth(),
            ) {
                ButtonRow(text = config.text)
            }
        }
    }
}

@Composable
private fun ButtonRow(text: String) {
    Row(Modifier.fillMaxWidth()) {
        Text(
            text = text,
            textAlign = TextAlign.Center,
            modifier = Modifier.weight(1f)
        )
    }
}

@ThemeModePreviews
@Composable
private fun SuccessDefaultPreview() {
    PreviewTheme {
        SuccessScreenView(
            state = State(
                successConfig = SuccessUIConfig(
                    textElementsConfig = SuccessUIConfig.TextElementsConfig(
                        text = stringResource(R.string.generic_success),
                        description = stringResource(R.string.generic_success),
                    ),
                    imageConfig = SuccessUIConfig.ImageConfig(),
                    buttonConfig = listOf(
                        SuccessUIConfig.ButtonConfig(
                            text = "Back",
                            style = SuccessUIConfig.ButtonConfig.Style.PRIMARY,
                            navigation = ConfigNavigation(
                                navigationType = NavigationType.PopTo(StartupScreens.Splash),
                            )
                        )
                    ),
                    onBackScreenToNavigate = ConfigNavigation(
                        navigationType = NavigationType.PopTo(StartupScreens.Splash),
                    ),
                )
            ),
            effectFlow = Channel<Effect>().receiveAsFlow(),
            onEventSent = {},
            onNavigationRequested = {},
            paddingValues = PaddingValues(SIZE_MEDIUM.dp)
        )
    }
}

@ThemeModePreviews
@Composable
private fun SuccessPendingPreview() {
    PreviewTheme {
        SuccessScreenView(
            state = State(
                successConfig = SuccessUIConfig(
                    textElementsConfig = SuccessUIConfig.TextElementsConfig(
                        text = stringResource(R.string.issuance_add_document_deferred_success_text),
                        description = stringResource(R.string.issuance_add_document_deferred_success_description),
                        color = ThemeColors.pending,
                    ),
                    imageConfig = SuccessUIConfig.ImageConfig(
                        type = SuccessUIConfig.ImageConfig.Type.Drawable(icon = AppIcons.InProgress),
                        tint = ThemeColors.primary,
                        screenPercentageSize = PERCENTAGE_25,
                    ),
                    buttonConfig = listOf(
                        SuccessUIConfig.ButtonConfig(
                            text = "back",
                            style = SuccessUIConfig.ButtonConfig.Style.PRIMARY,
                            navigation = ConfigNavigation(
                                navigationType = NavigationType.PopTo(StartupScreens.Splash),
                            )
                        )
                    ),
                    onBackScreenToNavigate = ConfigNavigation(
                        navigationType = NavigationType.PopTo(StartupScreens.Splash),
                    ),
                )
            ),
            effectFlow = Channel<Effect>().receiveAsFlow(),
            onEventSent = {},
            onNavigationRequested = {},
            paddingValues = PaddingValues(SIZE_MEDIUM.dp)
        )
    }
}