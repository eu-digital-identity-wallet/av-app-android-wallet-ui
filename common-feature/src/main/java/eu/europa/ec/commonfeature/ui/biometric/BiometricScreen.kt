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

package eu.europa.ec.commonfeature.ui.biometric

import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import eu.europa.ec.commonfeature.config.BiometricMode
import eu.europa.ec.commonfeature.config.BiometricUiConfig
import eu.europa.ec.commonfeature.config.OnBackNavigationConfig
import eu.europa.ec.commonfeature.util.TestTag
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.uilogic.component.AppIcons
import eu.europa.ec.uilogic.component.content.ContentHeader
import eu.europa.ec.uilogic.component.content.ContentHeaderConfig
import eu.europa.ec.uilogic.component.content.ContentScreen
import eu.europa.ec.uilogic.component.content.ImePaddingConfig
import eu.europa.ec.uilogic.component.content.ScreenNavigateAction
import eu.europa.ec.uilogic.component.preview.PreviewTheme
import eu.europa.ec.uilogic.component.preview.ThemeModePreviews
import eu.europa.ec.uilogic.component.utils.OneTimeLaunchedEffect
import eu.europa.ec.uilogic.component.utils.SIZE_MEDIUM
import eu.europa.ec.uilogic.component.utils.SPACING_SMALL
import eu.europa.ec.uilogic.component.utils.VSpacer
import eu.europa.ec.uilogic.component.wrap.OtpTextField
import eu.europa.ec.uilogic.component.wrap.PinHintText
import eu.europa.ec.uilogic.component.wrap.TextConfig
import eu.europa.ec.uilogic.component.wrap.WrapIconButton
import eu.europa.ec.uilogic.component.wrap.WrapImage
import eu.europa.ec.uilogic.component.wrap.WrapLink
import eu.europa.ec.uilogic.component.wrap.WrapLinkData
import eu.europa.ec.uilogic.component.wrap.WrapText
import eu.europa.ec.uilogic.config.ConfigNavigation
import eu.europa.ec.uilogic.config.FlowCompletion
import eu.europa.ec.uilogic.config.NavigationType
import eu.europa.ec.uilogic.extension.cacheDeepLink
import eu.europa.ec.uilogic.extension.finish
import eu.europa.ec.uilogic.extension.paddingFrom
import eu.europa.ec.uilogic.extension.resetBackStack
import eu.europa.ec.uilogic.extension.setBackStackFlowCancelled
import eu.europa.ec.uilogic.extension.setBackStackFlowSuccess
import eu.europa.ec.uilogic.navigation.CommonScreens
import eu.europa.ec.uilogic.navigation.helper.handleDeepLinkAction
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch

@Composable
fun BiometricScreen(
    navController: NavController,
    viewModel: BiometricViewModel
) {
    val state: State by viewModel.viewState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    ContentScreen(
        isLoading = state.isLoading,
        navigatableAction = if (state.isBackable) {
            ScreenNavigateAction.BACKABLE
        } else {
            ScreenNavigateAction.NONE
        },
        onBack = {
            viewModel.setEvent(Event.OnNavigateBack)
        },
        contentErrorConfig = state.error,
        imePaddingConfig = ImePaddingConfig.ONLY_CONTENT
    ) {
        Body(
            state = state,
            effectFlow = viewModel.effect,
            onEventSent = { event -> viewModel.setEvent(event) },
            onNavigationRequested = { navigationEffect ->
                when (navigationEffect) {
                    is Effect.Navigation.SwitchScreen -> {
                        navController.navigate(navigationEffect.screen) {
                            popUpTo(CommonScreens.Biometric.screenRoute) { inclusive = true }
                        }
                    }

                    is Effect.Navigation.LaunchBiometricsSystemScreen -> {
                        viewModel.setEvent(Event.LaunchBiometricSystemScreen)
                    }

                    is Effect.Navigation.PopBackStackUpTo -> {
                        when (navigationEffect.indicateFlowCompletion) {
                            FlowCompletion.CANCEL -> {
                                navController.setBackStackFlowCancelled(
                                    navigationEffect.screenRoute
                                )
                            }

                            FlowCompletion.SUCCESS -> {
                                navController.setBackStackFlowSuccess(
                                    navigationEffect.screenRoute
                                )
                            }

                            FlowCompletion.NONE -> {
                                navController.resetBackStack(
                                    navigationEffect.screenRoute
                                )
                            }
                        }
                        navController.popBackStack(
                            route = navigationEffect.screenRoute,
                            inclusive = navigationEffect.inclusive
                        )
                    }

                    is Effect.Navigation.Deeplink -> {
                        navigationEffect.routeToPop?.let { route ->
                            context.cacheDeepLink(navigationEffect.link)
                            if (navigationEffect.isPreAuthorization) {
                                navController.navigate(route) {
                                    popUpTo(CommonScreens.Biometric.screenRoute) {
                                        inclusive = true
                                    }
                                }
                            } else {
                                navController.popBackStack(
                                    route = route,
                                    inclusive = false
                                )
                            }
                        } ?: handleDeepLinkAction(navController, navigationEffect.link)

                    }

                    is Effect.Navigation.Pop -> navController.popBackStack()
                    is Effect.Navigation.Finish -> context.finish()
                }
            },
            padding = it
        )
    }

    OneTimeLaunchedEffect {
        viewModel.setEvent(Event.Init)
    }
}

@Composable
private fun Body(
    state: State,
    effectFlow: Flow<Effect>,
    onEventSent: ((event: Event) -> Unit),
    onNavigationRequested: ((navigationEffect: Effect.Navigation) -> Unit),
    padding: PaddingValues
) {

    // Get application context.
    val context = LocalContext.current

    Column(
        Modifier
            .fillMaxSize()
            .paddingFrom(padding, bottom = false)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
        ) {
            MainContent(
                state = state,
                onEventSent = onEventSent,
            )
        }

        if (state.userBiometricsAreEnabled) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .navigationBarsPadding()
                    .padding(bottom = 5.dp),
                horizontalArrangement = Arrangement.End,
            ) {
                WrapIconButton(
                    iconData = AppIcons.TouchId,
                    onClick = {
                        onEventSent(
                            Event.OnBiometricsClicked(
                                context = context,
                                shouldThrowErrorIfNotAvailable = true
                            )
                        )
                    }
                )
            }
        }
    }

    LaunchedEffect(Unit) {
        effectFlow.onEach { effect ->
            when (effect) {
                is Effect.Navigation -> {
                    onNavigationRequested(effect)
                }

                is Effect.InitializeBiometricAuthOnCreate -> {
                    onEventSent(
                        Event.OnBiometricsClicked(
                            context = context,
                            shouldThrowErrorIfNotAvailable = false,
                        )
                    )
                }
            }
        }.collect()
    }
}

@Composable
private fun MainContent(
    state: State,
    onEventSent: (event: Event) -> Unit
) {
    when (val mode = state.config.mode) {
        is BiometricMode.Default -> {
            VerifyIdentity(state, mode, onEventSent)
        }

        is BiometricMode.Login -> {
            LoginOnAppStartup(mode, state, onEventSent)
        }
    }
}

@Composable
private fun LoginOnAppStartup(
    mode: BiometricMode.Login,
    state: State,
    onEventSent: (event: Event) -> Unit
) {
    val scrollState = rememberScrollState()
    val coroutineScope = rememberCoroutineScope()

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .imePadding()
            .verticalScroll(scrollState),
    ) {
        VSpacer.Custom(80)

        WrapImage(
            modifier = Modifier.align(Alignment.CenterHorizontally),
            iconData = AppIcons.LogoPlain
        )
        VSpacer.ExtraLarge()
        WrapText(
            textConfig = TextConfig(
                style = MaterialTheme.typography.titleLarge,
                maxLines = Int.MAX_VALUE,
                isHeading = true
            ),
            text = mode.title
        )

        VSpacer.Large()

        val subtitle = if (state.userBiometricsAreEnabled) {
            mode.subTitleWhenBiometricsEnabled
        } else {
            mode.subTitleWhenBiometricsNotEnabled
        }
        WrapText(
            textConfig = TextConfig(style = MaterialTheme.typography.bodyLarge),
            text = subtitle
        )
        VSpacer.Large()
        PinFieldLayout(
            state = state,
            onPinInput = { quickPin ->
                onEventSent(Event.OnQuickPinEntered(quickPin))
            }
        )
        if (!state.userBiometricsAreEnabled) {
            WrapLink(WrapLinkData(R.string.biometric_login_forgot_pin)) {
                //handle forgot pin click
            }
        }
    }

    AutoScrollToBottom(state, coroutineScope, scrollState)
}

@Composable
private fun AutoScrollToBottom(
    state: State,
    coroutineScope: CoroutineScope,
    scrollState: ScrollState,
) {
    LaunchedEffect(state.quickPinError, state.quickPin) {
        if (state.quickPin.isNotEmpty() || !state.quickPinError.isNullOrEmpty()) {
            coroutineScope.launch {
                scrollState.scrollTo(scrollState.maxValue)
            }
        }
    }
}

@Composable
private fun VerifyIdentity(
    state: State,
    mode: BiometricMode.Default,
    onEventSent: (event: Event) -> Unit
) {
    val scrollState = rememberScrollState()
    val coroutineScope = rememberCoroutineScope()

    val description = if (state.userBiometricsAreEnabled) {
        mode.descriptionWhenBiometricsEnabled
    } else {
        mode.descriptionWhenBiometricsNotEnabled
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .imePadding()
            .verticalScroll(scrollState)
    ) {
        ContentHeader(
            modifier = Modifier.fillMaxWidth(),
            config = ContentHeaderConfig(description = description)
        )

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = SPACING_SMALL.dp)
            ) {
                Text(
                    modifier = Modifier
                        .testTag(TestTag.BiometricScreen.PIN_TEXT)
                        .fillMaxWidth()
                        .padding(vertical = SPACING_SMALL.dp),
                    text = mode.textAbovePin,
                    style = MaterialTheme.typography.titleMedium.copy(
                        color = MaterialTheme.colorScheme.onSurface
                    )
                )

            PinFieldLayout(
                state = state,
                onPinInput = { quickPin ->
                    onEventSent(Event.OnQuickPinEntered(quickPin))
                }
            )
        }
    }

    AutoScrollToBottom(
        state = state,
        coroutineScope = coroutineScope,
        scrollState = scrollState
    )
}

@Composable
private fun PinFieldLayout(
    modifier: Modifier = Modifier,
    state: State,
    onPinInput: (String) -> Unit,
) {
    val pinHintText = stringResource(R.string.quick_pin_create_enter_subtitle)
    PinHintText(pinHintText)

    OtpTextField(
        modifier = modifier,
        onUpdate = onPinInput,
        length = state.quickPinSize,
        hasError = !state.quickPinError.isNullOrEmpty(),
        errorMessage = state.quickPinError,
        visualTransformation = PasswordVisualTransformation(),
        pinWidth = 42.dp,
        focusOnCreate = !state.userBiometricsAreEnabled,
        otpText = state.quickPin,
        enabled = !state.isLockedOut
    )
}

/**
 * Preview composable of [Body].
 */
@ThemeModePreviews
@Composable
private fun PreviewBiometricDefaultScreen() {
    val defaultMode = BiometricMode.Default(
        descriptionWhenBiometricsEnabled = stringResource(R.string.loading_biometry_biometrics_enabled_description),
        descriptionWhenBiometricsNotEnabled = stringResource(R.string.loading_biometry_biometrics_not_enabled_description),
        textAbovePin = stringResource(R.string.biometric_default_mode_text_above_pin_field),
    )
    PreviewTheme {
        Body(
            state = State(
                config = BiometricUiConfig(
                    mode = defaultMode,
                    isPreAuthorization = true,
                    onSuccessNavigation = ConfigNavigation(
                        navigationType = NavigationType.PushScreen(CommonScreens.Biometric)
                    ),
                    onBackNavigationConfig = OnBackNavigationConfig(
                        onBackNavigation = ConfigNavigation(
                            navigationType = NavigationType.PushScreen(CommonScreens.Biometric),
                        ),
                        hasToolbarBackIcon = true
                    )
                ),
                userBiometricsAreEnabled = false,
            ),
            effectFlow = Channel<Effect>().receiveAsFlow(),
            onEventSent = {},
            onNavigationRequested = {},
            padding = PaddingValues(SIZE_MEDIUM.dp)
        )
    }
}

/**
 * Preview composable of [Body].
 */
@ThemeModePreviews
@Composable
private fun PreviewBiometricLoginScreen() {
    val loginMode = BiometricMode.Login(
        title = stringResource(R.string.biometric_login_title),
        subTitleWhenBiometricsEnabled = stringResource(R.string.loading_biometry_biometrics_enabled_description),
        subTitleWhenBiometricsNotEnabled = stringResource(R.string.loading_biometry_biometrics_not_enabled_description),
    )
    PreviewTheme {

        Body(
            state = State(
                config = BiometricUiConfig(
                    mode = loginMode,
                    isPreAuthorization = true,
                    onSuccessNavigation = ConfigNavigation(
                        navigationType = NavigationType.PushScreen(CommonScreens.Biometric)
                    ),
                    onBackNavigationConfig = OnBackNavigationConfig(
                        onBackNavigation = ConfigNavigation(
                            navigationType = NavigationType.PushScreen(CommonScreens.Biometric),
                        ),
                        hasToolbarBackIcon = true
                    )
                )
            ),
            effectFlow = Channel<Effect>().receiveAsFlow(),
            onEventSent = {},
            onNavigationRequested = {},
            padding = PaddingValues(SIZE_MEDIUM.dp)
        )
    }
}