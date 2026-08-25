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

@file:OptIn(ExperimentalMaterial3Api::class)

package eu.europa.ec.landingfeature.ui.settings

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.uilogic.component.AppIcons
import eu.europa.ec.uilogic.component.content.ContentScreen
import eu.europa.ec.uilogic.component.content.ScreenNavigateAction
import eu.europa.ec.uilogic.component.preview.PreviewTheme
import eu.europa.ec.uilogic.component.preview.ThemeModePreviews
import eu.europa.ec.uilogic.component.utils.SIZE_SMALL
import eu.europa.ec.uilogic.component.utils.SPACING_EXTRA_LARGE
import eu.europa.ec.uilogic.component.utils.VSpacer
import eu.europa.ec.uilogic.component.wrap.BottomSheetTextDataUi
import eu.europa.ec.uilogic.component.wrap.DialogBottomSheet
import eu.europa.ec.uilogic.component.wrap.TextConfig
import eu.europa.ec.uilogic.component.wrap.WrapImage
import eu.europa.ec.uilogic.component.wrap.WrapModalBottomSheet
import eu.europa.ec.uilogic.component.wrap.WrapText
import eu.europa.ec.uilogic.extension.getAppVersionCode
import eu.europa.ec.uilogic.extension.getAppVersionName
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.onEach

@Composable
fun SettingsScreen(navController: NavController, viewModel: SettingsViewModel) {
    val state = viewModel.viewState.collectAsStateWithLifecycle()
    val bottomSheetState = rememberModalBottomSheetState(
        skipPartiallyExpanded = false
    )
    ContentScreen(
        isLoading = state.value.isLoading,
        navigatableAction = ScreenNavigateAction.BACKABLE,
        onBack = { viewModel.setEvent(Event.GoBack) },
    ) { paddingValues ->
        Content(
            paddingValues = paddingValues,
            effectFlow = viewModel.effect,
            onNavigationRequested = { navigationEffect ->
                handleNavigationEffect(navigationEffect, navController)
            },
            onEvent = { viewModel.setEvent(it) })

        val isBottomSheetOpen = state.value.showDeleteProofsDialog
        if (isBottomSheetOpen) {
            WrapModalBottomSheet(
                onDismissRequest = {
                    viewModel.setEvent(Event.BottomSheetEvent.DeleteProofsDismissed)
                },
                sheetState = bottomSheetState
            ) {
                ConfirmDeleteDialogContent(
                    onEvent = { viewModel.setEvent(it) }
                )
            }
        }
    }
}

@Composable
private fun Content(
    paddingValues: PaddingValues,
    effectFlow: Flow<Effect>,
    onNavigationRequested: (Effect.Navigation) -> Unit,
    onEvent: (Event) -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(paddingValues)
            .verticalScroll(rememberScrollState())
    ) {
        Row {
            WrapImage(
                modifier = Modifier
                    .height(40.dp)
                    .align(Alignment.CenterVertically),
                iconData = AppIcons.Settings,
                contentScale = ContentScale.Fit,
            )
            WrapText(
                text = stringResource(R.string.settings_screen_title),
                textConfig = TextConfig(style = MaterialTheme.typography.headlineLarge)
            )
        }

        SettingsSection(onEvent)
    }

    LaunchedEffect(Unit) {
        effectFlow.onEach { effect ->
            when (effect) {
                is Effect.Navigation -> onNavigationRequested(effect)
            }
        }.collect()
    }
}

private fun handleNavigationEffect(
    navigationEffect: Effect.Navigation,
    navController: NavController,
) {
    when (navigationEffect) {
        is Effect.Navigation.SwitchScreen -> {
            navController.navigate(navigationEffect.screenRoute)
        }

        is Effect.Navigation.Pop -> {
            navController.popBackStack()
        }
    }
}

@Composable
fun SettingsSection(onEvent: (Event) -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 0.dp, vertical = SPACING_EXTRA_LARGE.dp),
    ) {

        AppInfo()
        CredentialsSettings(onEvent)
        VSpacer.Large()
        SecuritySettings(onEvent)

    }
}

@Composable
fun AppInfo() {
    WrapText(
        modifier = Modifier
            .fillMaxWidth(),
        text = stringResource(R.string.settings_screen_app_info),
        textConfig = TextConfig(
            style = MaterialTheme.typography.titleMedium,
        )
    )
    VSpacer.Small()
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        WrapText(
            modifier = Modifier,
            text = stringResource(R.string.settings_screen_version),
            textConfig = TextConfig(
                style = MaterialTheme.typography.bodyMedium,
            )
        )
        VersionNumber()

    }
    VSpacer.ExtraLarge()
}

@Composable
private fun VersionNumber() {
    val context = LocalContext.current
    val versionCode = context.getAppVersionCode()
    val versionName = context.getAppVersionName()

    WrapText(
        text = "$versionName($versionCode)",
        textConfig = TextConfig(
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,

        )
    )
}

@Composable
private fun CredentialsSettings(onEvent: (Event) -> Unit) {
    WrapText(
        modifier = Modifier
            .fillMaxWidth(),
        text = stringResource(R.string.settings_screen_credentials),
        textConfig = TextConfig(
            style = MaterialTheme.typography.titleMedium,
        )
    )
    WrapText(
        modifier = Modifier
            .fillMaxWidth()
            .clickable {
                onEvent(Event.DeleteProofsClicked)
            }
            .padding(vertical = SIZE_SMALL.dp),
        text = stringResource(R.string.settings_screen_delete_proofs),
        textConfig = TextConfig(
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error,
        )
    )
}
@Composable
private fun SecuritySettings(onEvent: (Event) -> Unit) {
    WrapText(
        modifier = Modifier
            .fillMaxWidth(),
        text = stringResource(R.string.settings_screen_security),
        textConfig = TextConfig(
            style = MaterialTheme.typography.titleMedium,
        )
    )
    WrapText(
        modifier = Modifier
            .fillMaxWidth()
            .clickable {
                onEvent(Event.ChangePinClicked)
            }
            .padding(vertical = SIZE_SMALL.dp),
        text = stringResource(R.string.settings_screen_change_pin),
        textConfig = TextConfig(
            style = MaterialTheme.typography.bodyMedium,
        )
    )
}

@Composable
private fun ConfirmDeleteDialogContent(
    onEvent: (event: Event) -> Unit
) {
    DialogBottomSheet(
        textData = BottomSheetTextDataUi(
            title = stringResource(id = R.string.confirm_doc_removal_dialog_title),
            message = stringResource(id = R.string.confirm_doc_removal_dialog_text),
            positiveButtonText = stringResource(id = R.string.confirm_doc_removal_dialog_delete),
            negativeButtonText = stringResource(id = R.string.generic_cancel),
        ),
        onPositiveClick = { onEvent(Event.BottomSheetEvent.DeleteProofsConfirmed) },
        onNegativeClick = { onEvent(Event.BottomSheetEvent.DeleteProofsDismissed) }
    )
}

@ThemeModePreviews
@Composable
private fun ContentPreview() {
    PreviewTheme {
        Content(
            paddingValues = PaddingValues(10.dp),
            effectFlow = flowOf(),
            onNavigationRequested = {},
            onEvent = { }
        )
    }
}

@ThemeModePreviews
@Composable
private fun ConfirmDeleteDialogContentPreview() {
    PreviewTheme {
        ConfirmDeleteDialogContent(onEvent = {})
    }
}
