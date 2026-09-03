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

package eu.europa.ec.onboardingfeature.ui.tokenqr

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.uilogic.component.AppIcons.QrScanner
import eu.europa.ec.uilogic.component.TopStepBar
import eu.europa.ec.uilogic.component.content.ContentScreen
import eu.europa.ec.uilogic.component.content.ScreenNavigateAction.NONE
import eu.europa.ec.uilogic.component.preview.PreviewTheme
import eu.europa.ec.uilogic.component.utils.VSpacer
import eu.europa.ec.uilogic.component.wrap.ButtonConfig
import eu.europa.ec.uilogic.component.wrap.ButtonType.PRIMARY
import eu.europa.ec.uilogic.component.wrap.ButtonType.SECONDARY
import eu.europa.ec.uilogic.component.wrap.StickyBottomConfig
import eu.europa.ec.uilogic.component.wrap.StickyBottomType.TwoButtons
import eu.europa.ec.uilogic.component.wrap.TextConfig
import eu.europa.ec.uilogic.component.wrap.WrapImage
import eu.europa.ec.uilogic.component.wrap.WrapStickyBottomContent
import eu.europa.ec.uilogic.component.wrap.WrapText
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.onEach

@Composable
fun TokenQrIntroScreen(
    hostNavController: NavController,
    viewModel: TokenQrIntroViewModel,
) {
    val state by viewModel.viewState.collectAsStateWithLifecycle()

    ContentScreen(
        isLoading = state.isLoading,
        navigatableAction = NONE,
        onBack = { viewModel.setEvent(Event.OnBackPressed) },
        contentErrorConfig = state.error,
        stickyBottom = { paddingValues ->
            ActionButtons(
                paddingValues = paddingValues,
                onBackPressed = { viewModel.setEvent(Event.OnBackPressed) },
                onScanClicked = { viewModel.setEvent(Event.OnScanClicked) },
            )
        }
    ) { paddingValues ->
        Content(paddingValues = paddingValues)
    }

    LaunchedEffect(Unit) {
        viewModel.effect.onEach { effect ->
            when (effect) {
                Effect.Navigation.GoBack -> hostNavController.popBackStack()
                is Effect.Navigation.SwitchScreen -> hostNavController.navigate(effect.screenRoute)
            }
        }.collect()
    }
}

@Composable
private fun ActionButtons(
    paddingValues: PaddingValues,
    onBackPressed: () -> Unit,
    onScanClicked: () -> Unit,
) {
    val buttons = TwoButtons(
        primaryButtonConfig = ButtonConfig(
            type = SECONDARY,
            onClick = { onBackPressed() },
        ),
        secondaryButtonConfig = ButtonConfig(
            type = PRIMARY,
            onClick = { onScanClicked() },
        ),
    )

    WrapStickyBottomContent(
        modifier = Modifier
            .fillMaxWidth()
            .padding(paddingValues),
        stickyBottomConfig = StickyBottomConfig(type = buttons, showDivider = false)
    ) {
        when (it?.type) {
            PRIMARY -> Text(text = stringResource(R.string.generic_scan_qr))
            SECONDARY -> Text(text = stringResource(R.string.generic_back))
            else -> {}
        }
    }
}

@Composable
private fun Content(
    paddingValues: PaddingValues,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(paddingValues)
            .verticalScroll(rememberScrollState())
    ) {
        TopStepBar(currentStep = 3)
        VSpacer.ExtraLarge()

        Row(modifier = Modifier.fillMaxWidth()) {
            WrapImage(
                modifier = Modifier.size(64.dp),
                iconData = QrScanner,
            )
        }

        VSpacer.ExtraLarge()

        WrapText(
            text = stringResource(R.string.onboarding_token_qr_intro_title),
            textConfig = TextConfig(
                style = MaterialTheme.typography.titleLarge,
                maxLines = Int.MAX_VALUE,
                isHeading = true
            ),
        )

        VSpacer.Large()

        WrapText(
            text = stringResource(R.string.onboarding_token_qr_intro_description),
            textConfig = TextConfig(
                style = MaterialTheme.typography.bodyLarge,
                maxLines = Int.MAX_VALUE,
            ),
        )

        VSpacer.ExtraLarge()
    }
}

@Preview
@Composable
private fun TokenQrIntroScreenPreview() {
    PreviewTheme {
        ContentScreen(
            isLoading = false,
            navigatableAction = NONE,
            stickyBottom = { paddingValues ->
                ActionButtons(
                    paddingValues = paddingValues,
                    onBackPressed = {},
                    onScanClicked = {},
                )
            }
        ) { paddingValues ->
            Content(paddingValues = paddingValues)
        }
    }
}
