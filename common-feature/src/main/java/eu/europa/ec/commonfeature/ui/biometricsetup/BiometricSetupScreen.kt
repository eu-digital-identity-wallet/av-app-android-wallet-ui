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

package eu.europa.ec.commonfeature.ui.biometricsetup

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle.Event.ON_RESUME
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import eu.europa.ec.commonfeature.ui.biometricsetup.Effect.Navigation
import eu.europa.ec.commonfeature.ui.biometricsetup.Effect.Navigation.SwitchScreen
import eu.europa.ec.commonfeature.ui.biometricsetup.Event.NextButtonPressed
import eu.europa.ec.commonfeature.ui.biometricsetup.Event.ScreenResumed
import eu.europa.ec.commonfeature.ui.biometricsetup.Event.SkipButtonPressed
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.uilogic.component.TopStepBar
import eu.europa.ec.uilogic.component.content.ContentScreen
import eu.europa.ec.uilogic.component.content.ScreenNavigateAction
import eu.europa.ec.uilogic.component.preview.PreviewTheme
import eu.europa.ec.uilogic.component.preview.ThemeModePreviews
import eu.europa.ec.uilogic.component.utils.LifecycleEffect
import eu.europa.ec.uilogic.component.utils.VSpacer
import eu.europa.ec.uilogic.component.wrap.ButtonConfig
import eu.europa.ec.uilogic.component.wrap.ButtonType
import eu.europa.ec.uilogic.component.wrap.StickyBottomConfig
import eu.europa.ec.uilogic.component.wrap.StickyBottomType
import eu.europa.ec.uilogic.component.wrap.TextConfig
import eu.europa.ec.uilogic.component.wrap.WrapStickyBottomContent
import eu.europa.ec.uilogic.component.wrap.WrapText
import eu.europa.ec.uilogic.navigation.CommonScreens
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
fun BiometricSetupScreen(navController: NavController, viewModel: BiometricSetupViewModel) {
    val state: State by viewModel.viewState.collectAsStateWithLifecycle()
    val title = stringResource(id = R.string.biometric_setup_title)
    val appName = stringResource(R.string.landing_screen_title)
    val descriptionWithAppName = stringResource(
        id = R.string.biometric_setup_description,
        appName
    )

    ContentScreen(
        isLoading = state.isLoading,
        navigatableAction = ScreenNavigateAction.NONE,
        onBack = {
            if (!state.isSetupMandatory) {
                viewModel.setEvent(SkipButtonPressed)
            }
        },
        stickyBottom = { paddingValues ->
            ActionButtons(
                viewModel = viewModel,
                paddingValues = paddingValues,
                biometricsAvailable = state.isBiometricsAvailable,
                setupMandatory = state.isSetupMandatory,
            )
        }) { paddingValues ->
        Content(
            title = title,
            description = descriptionWithAppName,
            state = state,
            effectFlow = viewModel.effect,
            onNavigationRequested = { navigationEffect ->
                handleNavigationEffect(navController, navigationEffect)
            },
            paddingValues = paddingValues
        )
    }

    ObserveScreenResume(viewModel)
}

@Composable
private fun ActionButtons(
    viewModel: BiometricSetupViewModel,
    paddingValues: PaddingValues,
    biometricsAvailable: Boolean,
    setupMandatory: Boolean,
) {
    val context = LocalContext.current
    val buttons = if (setupMandatory) {
        StickyBottomType.OneButton(
            config = ButtonConfig(
                type = ButtonType.PRIMARY,
                enabled = biometricsAvailable,
                onClick = { viewModel.setEvent(NextButtonPressed(context)) }
            )
        )
    } else {
        StickyBottomType.TwoButtons(
            primaryButtonConfig = ButtonConfig(
                type = ButtonType.SECONDARY,
                onClick = { viewModel.setEvent(SkipButtonPressed) }),
            secondaryButtonConfig = ButtonConfig(
                type = ButtonType.PRIMARY,
                enabled = biometricsAvailable,
                onClick = { viewModel.setEvent(NextButtonPressed(context)) })
        )
    }
    WrapStickyBottomContent(
        modifier = Modifier
            .fillMaxWidth()
            .padding(paddingValues),
        stickyBottomConfig = StickyBottomConfig(type = buttons, showDivider = false)
    ) {
        when (it?.type) {
            ButtonType.PRIMARY -> Text(text = stringResource(id = R.string.biometric_setup_enable))
            ButtonType.SECONDARY -> Text(text = stringResource(id = R.string.biometric_setup_skip))
            else -> {}
        }
    }
}

@Composable
private fun ObserveScreenResume(viewModel: BiometricSetupViewModel) {
    LifecycleEffect(
        lifecycleOwner = LocalLifecycleOwner.current,
        lifecycleEvent = ON_RESUME
    ) {
        viewModel.setEvent(ScreenResumed)
    }
}

@Composable
private fun Content(
    title: String,
    description: String,
    state: State,
    effectFlow: Flow<Effect>,
    onNavigationRequested: (Navigation) -> Unit,
    paddingValues: PaddingValues
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(paddingValues)
    ) {
        TopStepBar(currentStep = 2)

        VSpacer.ExtraLarge()

        WrapText(
            textConfig = TextConfig(style = MaterialTheme.typography.titleLarge, maxLines = 4),
            text = title
        )

        VSpacer.Large()

        WrapText(
            textConfig = TextConfig(style = MaterialTheme.typography.bodyMedium, maxLines = 6),
            text = description
        )

        state.biometricsError?.let { error ->
            ErrorText(error)
        }
    }

    LaunchedEffect(Unit) {
        effectFlow.onEach { effect ->
            when (effect) {
                is Navigation -> onNavigationRequested(effect)
            }
        }.collect()
    }
}

@Composable
private fun ErrorText(error: String) {
    VSpacer.Medium()
    WrapText(
        textConfig = TextConfig(
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
            maxLines = 5
        ), text = error
    )
}

private fun handleNavigationEffect(
    navController: NavController,
    navigationEffect: Navigation,
) {
    when (navigationEffect) {
        is SwitchScreen -> {
            navController.navigate(navigationEffect.screen) {
                popUpTo(CommonScreens.BiometricSetup.screenRoute) { inclusive = true }
            }
        }
    }
}

@ThemeModePreviews
@Composable
private fun BiometricSetupScreenPreview() {
    PreviewTheme {
        Content(
            title = "Biometrically unlock the app",
            description = "Use your fingerprint or facial recognition to log in to the app.",
            state = State(isBiometricsAvailable = true),
            effectFlow = Channel<Effect>().receiveAsFlow(),
            onNavigationRequested = {},
            paddingValues = PaddingValues(16.dp)
        )
    }
}

@ThemeModePreviews
@Composable
private fun BiometricSetupScreenErrorPreview() {
    PreviewTheme {
        Content(
            title = "Biometrically unlock the app",
            description = "Use your fingerprint or facial recognition to log in to the app.",
            state = State(
                isBiometricsAvailable = false,
                biometricsError = "Biometric authentication is not available on this device."
            ),
            effectFlow = Channel<Effect>().receiveAsFlow(),
            onNavigationRequested = {},
            paddingValues = PaddingValues(16.dp)
        )
    }
}
