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

package eu.europa.ec.onboardingfeature.ui.passport.passportbiometrics

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.uilogic.component.AppIcons
import eu.europa.ec.uilogic.component.PassportVerificationStepBar
import eu.europa.ec.uilogic.component.content.ContentScreen
import eu.europa.ec.uilogic.component.content.ScreenNavigateAction
import eu.europa.ec.uilogic.component.preview.PreviewTheme
import eu.europa.ec.uilogic.component.preview.ThemeModePreviews
import eu.europa.ec.uilogic.component.utils.VSpacer
import eu.europa.ec.uilogic.component.wrap.ButtonConfig
import eu.europa.ec.uilogic.component.wrap.ButtonType
import eu.europa.ec.uilogic.component.wrap.StickyBottomConfig
import eu.europa.ec.uilogic.component.wrap.StickyBottomType
import eu.europa.ec.uilogic.component.wrap.TextConfig
import eu.europa.ec.uilogic.component.wrap.WrapImage
import eu.europa.ec.uilogic.component.wrap.WrapLink
import eu.europa.ec.uilogic.component.wrap.WrapLinkData
import eu.europa.ec.uilogic.component.wrap.WrapStickyBottomContent
import eu.europa.ec.uilogic.component.wrap.WrapText

@Composable
fun PassportBiometricScreen(controller : NavController, viewModel: PassportBiometricViewModel) {

    val state by viewModel.viewState.collectAsStateWithLifecycle()

    ContentScreen(
        isLoading = state.isLoading,
        navigatableAction = ScreenNavigateAction.NONE,
        onBack = { viewModel.setEvent(Event.OnBackPressed) },
        stickyBottom = { paddingValues ->
            ActionButtons(
                onBack = { viewModel.setEvent(Event.OnBackPressed) },
                onCapture = { viewModel.setEvent(Event.OnNextPressed) },
                paddings = paddingValues
            )
        }
    ) { paddingValues -> Content(paddingValues = paddingValues) { viewModel.setEvent(Event.OnLinkPressed)} }

    LaunchedEffect(Unit) {
        viewModel.effect.collect { effect ->
            handleEffect(effect, controller)
        }
    }

    LaunchedEffect(Unit) {
        viewModel.setEvent(Event.OnInitEvent)
    }

}

@Composable
private fun ActionButtons(onBack: () -> Unit = {}, onCapture: () -> Unit = {}, paddings: PaddingValues) {

    val buttons = StickyBottomType.TwoButtons(
        primaryButtonConfig = ButtonConfig(
            type = ButtonType.SECONDARY,
            onClick = { onBack() }
        ),
        secondaryButtonConfig = ButtonConfig(
            type = ButtonType.PRIMARY,
            onClick = { onCapture() }
        )
    )

    WrapStickyBottomContent(
        modifier = Modifier
            .fillMaxWidth()
            .padding(paddings),
        stickyBottomConfig = StickyBottomConfig(type = buttons, showDivider = false)
    ) { buttonConfigs ->
        buttonConfigs?.let { buttonConfig ->
            when(buttonConfig.type) {
                ButtonType.PRIMARY -> Text(stringResource(R.string.passport_biometrics_next))
                ButtonType.SECONDARY -> Text(stringResource(R.string.passport_biometrics_back))
            }
        }
    }
}

private fun handleEffect(effect: Effect, hostNavController: NavController) {
    when (effect) {
        is Effect.Navigation.GoBack -> hostNavController.popBackStack()
        is Effect.Navigation.SwitchScreen -> hostNavController.navigate(effect.screenRoute)
    }
}


@Composable
private fun Content(paddingValues: PaddingValues, onLinkAction : () -> Unit) {

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(paddingValues)
            .verticalScroll(rememberScrollState())
    ) {

        PassportVerificationStepBar(1)

        VSpacer.ExtraLarge()
        WrapText(
            text = stringResource(R.string.passport_biometrics_first_header),
            textConfig = TextConfig(
                style = MaterialTheme.typography.titleLarge.copy(
                    fontWeight = FontWeight.SemiBold
                ),
                maxLines = Int.MAX_VALUE,
                isHeading = true
            ),
        )

        VSpacer.ExtraLarge()
        WrapImage(modifier = Modifier,
            iconData = AppIcons.PassportBiometrics,
            contentScale = ContentScale.Fit,
        )

        VSpacer.Large()
        WrapText(
            text = stringResource(R.string.passport_biometrics_first_description),
            textConfig = TextConfig(
                style = MaterialTheme.typography.bodyLarge,
                maxLines = Int.MAX_VALUE
            )
        )

        VSpacer.Large()
        WrapLink(data = WrapLinkData(textId = R.string.passport_biometrics_first_link)) { onLinkAction }
    }
}

@Composable
@ThemeModePreviews
fun PassportBiometricScreenPreview() {
    PreviewTheme {
        ContentScreen(
            navigatableAction = ScreenNavigateAction.NONE,
            stickyBottom = { paddingValues ->
                ActionButtons(
                    onBack = {},
                    onCapture = {},
                    paddings = paddingValues
                )
            }
        ) { paddingValues -> Content(paddingValues = paddingValues, {}) }
    }
}
