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

package eu.europa.ec.onboardingfeature.ui.passport.passportscanintro

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.uilogic.component.AppIcons
import eu.europa.ec.uilogic.component.NumberedList
import eu.europa.ec.uilogic.component.NumberedListItemData
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
import eu.europa.ec.uilogic.component.wrap.WrapStickyBottomContent
import eu.europa.ec.uilogic.component.wrap.WrapText
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.onEach

@Composable
fun PassportScanIntroScreen(
    hostNavController: NavController,
    viewModel: PassportScanIntroViewModel,
) {
    val state by viewModel.viewState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    ContentScreen(
        isLoading = state.isLoading,
        navigatableAction = ScreenNavigateAction.NONE,
        onBack = { viewModel.setEvent(Event.OnBackPressed) },
        contentErrorConfig = state.error,
        stickyBottom = { paddingValues ->
            ActionButtons(
                state = state,
                onBackPressed = { viewModel.setEvent(Event.OnBackPressed) },
                onDownloadClicked = { viewModel.setEvent(Event.OnDownloadClicked(context)) },
                onStartClicked = { viewModel.setEvent(Event.OnStartClicked) },
                paddingValues = paddingValues
            )
        }
    ) { paddingValues ->
        Content(paddingValues = paddingValues)
    }

    LaunchedEffect(Unit) {
        viewModel.effect.onEach { effect ->
            handleEffect(effect, hostNavController)
        }.collect()
    }
}

@Composable
private fun ActionButtons(
    state: State,
    onBackPressed: () -> Unit = {},
    onDownloadClicked: () -> Unit = {},
    onStartClicked: () -> Unit = {},
    paddingValues: PaddingValues,
) {
    val isDownloading = state.sdkReadiness == SdkReadiness.Downloading
    val isReady = state.sdkReadiness == SdkReadiness.Ready

    val primaryButtonOnClick = if (isReady) onStartClicked else onDownloadClicked

    val buttons = StickyBottomType.TwoButtons(
        primaryButtonConfig = ButtonConfig(
            type = ButtonType.SECONDARY,
            onClick = { onBackPressed() }
        ),
        secondaryButtonConfig = ButtonConfig(
            type = ButtonType.PRIMARY,
            enabled = !isDownloading,
            onClick = primaryButtonOnClick
        )
    )

    Column {
        AnimatedVisibility(visible = isDownloading && state.downloadProgress > 0) {
            LinearProgressIndicator(
                progress = { state.downloadProgress / 100f },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(paddingValues)
                    .padding(bottom = 8.dp),
            )
        }

        AnimatedVisibility(visible = !isReady) {
            WrapText(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(paddingValues),
                text = stringResource(R.string.passport_scan_intro_data_download_notice),
                textConfig = TextConfig(
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                    textAlign = TextAlign.Center,
                    maxLines = Int.MAX_VALUE
                ),
            )
        }

        WrapStickyBottomContent(
            modifier = Modifier
                .fillMaxWidth()
                .padding(paddingValues),
            stickyBottomConfig = StickyBottomConfig(type = buttons, showDivider = false)
        ) {
            when (it?.type) {
                ButtonType.PRIMARY -> {
                    val buttonText = when {
                        isReady -> stringResource(R.string.passport_scan_intro_start_button)
                        isDownloading -> stringResource(
                            R.string.passport_scan_intro_downloading_button,
                            state.downloadProgress
                        )
                        else -> stringResource(R.string.passport_scan_intro_download_button)
                    }
                    Text(text = buttonText)
                }
                ButtonType.SECONDARY -> Text(text = stringResource(R.string.passport_scan_intro_back_button))
                else -> {}
            }
        }
    }
}

private fun handleEffect(effect: Effect, hostNavController: NavController) {
    when (effect) {
        is Effect.Navigation.GoBack -> {
            hostNavController.popBackStack()
        }

        is Effect.Navigation.SwitchScreen -> {
            hostNavController.navigate(effect.screenRoute)
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
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.Center
        ) {
            WrapImage(
                modifier = Modifier.size(64.dp),
                iconData = AppIcons.Id,
            )
        }

        VSpacer.ExtraLarge()

        WrapText(
            text = stringResource(R.string.passport_scan_intro_enrollment_method),
            textConfig = TextConfig(
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
            ),
        )

        VSpacer.ExtraSmall()

        WrapText(
            text = stringResource(R.string.passport_scan_intro_title),
            textConfig = TextConfig(
                style = MaterialTheme.typography.titleLarge,
                maxLines = Int.MAX_VALUE,
                isHeading = true
            ),
        )

        VSpacer.Large()

        WrapText(
            text = stringResource(R.string.passport_scan_intro_description),
            textConfig = TextConfig(
                style = MaterialTheme.typography.bodyLarge,
                maxLines = Int.MAX_VALUE
            ),
        )

        VSpacer.Large()

        NumberedList(
            items = listOf(
                NumberedListItemData(
                    title = stringResource(R.string.passport_scan_intro_step_1_title),
                    description = stringResource(R.string.passport_scan_intro_step_1_description)
                ),
                NumberedListItemData(
                    title = stringResource(R.string.passport_scan_intro_step_2_title),
                    description = stringResource(R.string.passport_scan_intro_step_2_description)
                ),
                NumberedListItemData(
                    title = stringResource(R.string.passport_scan_intro_step_3_title),
                    description = stringResource(R.string.passport_scan_intro_step_3_description)
                ),
                NumberedListItemData(
                    title = stringResource(R.string.passport_scan_intro_step_5_title)
                )
            )
        )
    }
}

@ThemeModePreviews
@Composable
private fun PassportScanIntroScreenPreview() {
    PreviewTheme {
        ContentScreen(
            isLoading = false,
            navigatableAction = ScreenNavigateAction.NONE,
            onBack = {},
            stickyBottom = { paddingValues ->
                ActionButtons(
                    state = State(),
                    onBackPressed = {},
                    onDownloadClicked = {},
                    onStartClicked = {},
                    paddingValues = paddingValues
                )
            }
        ) { paddingValues ->
            Content(paddingValues = paddingValues)
        }
    }
}
