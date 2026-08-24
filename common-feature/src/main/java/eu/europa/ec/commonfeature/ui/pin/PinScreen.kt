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

package eu.europa.ec.commonfeature.ui.pin

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SheetState
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import eu.europa.ec.commonfeature.model.PinFlow
import eu.europa.ec.commonfeature.util.TestTag
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.uilogic.component.TopStepBar
import eu.europa.ec.uilogic.component.content.ContentScreen
import eu.europa.ec.uilogic.component.content.ImePaddingConfig
import eu.europa.ec.uilogic.component.content.ScreenNavigateAction
import eu.europa.ec.uilogic.component.preview.PreviewTheme
import eu.europa.ec.uilogic.component.preview.ThemeModePreviews
import eu.europa.ec.uilogic.component.utils.SPACING_EXTRA_LARGE
import eu.europa.ec.uilogic.component.utils.VSpacer
import eu.europa.ec.uilogic.component.wrap.BottomSheetTextDataUi
import eu.europa.ec.uilogic.component.wrap.ButtonConfig
import eu.europa.ec.uilogic.component.wrap.ButtonType
import eu.europa.ec.uilogic.component.wrap.DialogBottomSheet
import eu.europa.ec.uilogic.component.wrap.OtpTextField
import eu.europa.ec.uilogic.component.wrap.PinHintText
import eu.europa.ec.uilogic.component.wrap.StickyBottomConfig
import eu.europa.ec.uilogic.component.wrap.StickyBottomType
import eu.europa.ec.uilogic.component.wrap.TextConfig
import eu.europa.ec.uilogic.component.wrap.WrapModalBottomSheet
import eu.europa.ec.uilogic.component.wrap.WrapStickyBottomContent
import eu.europa.ec.uilogic.component.wrap.WrapText
import eu.europa.ec.uilogic.navigation.CommonScreens
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PinScreen(
    navController: NavController,
    viewModel: PinViewModel,
) {
    val state: State by viewModel.viewState.collectAsStateWithLifecycle()

    val isBottomSheetOpen = state.isBottomSheetOpen
    val scope = rememberCoroutineScope()
    val bottomSheetState = rememberModalBottomSheetState(
        skipPartiallyExpanded = true
    )

    ContentScreen(
        isLoading = state.isLoading,
        navigatableAction = state.action,
        onBack = { viewModel.setEvent(state.onBackEvent) },
        imePaddingConfig = ImePaddingConfig.ONLY_CONTENT,
        stickyBottom = { paddingValues ->
            WrapStickyBottomContent(
                modifier = Modifier
                    .testTag(TestTag.PinScreen.BUTTON)
                    .fillMaxWidth()
                    .padding(paddingValues),

                stickyBottomConfig = StickyBottomConfig(
                    type = StickyBottomType.OneButton(
                        config = ButtonConfig(
                            type = ButtonType.PRIMARY,
                            enabled = state.isButtonEnabled && !state.isLockedOut,
                            onClick = {
                                viewModel.setEvent(Event.NextButtonPressed(pin = state.pin))
                            }
                        )
                    ),
                    showDivider = false,
                )
            ) {
                Text(text = state.buttonText)
            }
        }
    ) { paddingValues ->
        Content(
            state = state,
            effectFlow = viewModel.effect,
            onEventSend = { event -> viewModel.setEvent(event) },
            onNavigationRequested = { navigationEffect ->
                handleNavigationEffect(
                    navigationEffect,
                    navController
                )
            },
            paddingValues = paddingValues,
            coroutineScope = scope,
            modalBottomSheetState = bottomSheetState,
        )

        if (isBottomSheetOpen) {
            WrapModalBottomSheet(
                onDismissRequest = {
                    viewModel.setEvent(
                        Event.BottomSheet.UpdateBottomSheetState(
                            isOpen = false
                        )
                    )
                },
                sheetState = bottomSheetState
            ) {
                SheetContent(
                    onEventSent = {
                        viewModel.setEvent(it)
                    }
                )
            }
        }
    }
}

private fun handleNavigationEffect(
    navigationEffect: Effect.Navigation,
    navController: NavController
) {
    when (navigationEffect) {
        is Effect.Navigation.SwitchScreen -> {
            navController.navigate(navigationEffect.screen) {
                popUpTo(CommonScreens.QuickPin.screenRoute) {
                    inclusive = true
                }
            }
        }

        is Effect.Navigation.Pop -> navController.popBackStack()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun Content(
    state: State,
    effectFlow: Flow<Effect>,
    onEventSend: (Event) -> Unit,
    onNavigationRequested: (Effect.Navigation) -> Unit,
    paddingValues: PaddingValues,
    coroutineScope: CoroutineScope,
    modalBottomSheetState: SheetState,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(paddingValues)
            .verticalScroll(rememberScrollState())
    ) {
        if (state.pinFlow == PinFlow.CREATE) {
            TopStepBar(
                currentStep = 2,
                topPadding = if (state.action == ScreenNavigateAction.NONE) {
                    SPACING_EXTRA_LARGE
                } else {
                    0
                }
            )
        }

        VSpacer.ExtraLarge()
        WrapText(
            textConfig = TextConfig(
                style = MaterialTheme.typography.titleLarge,
                maxLines = Int.MAX_VALUE,
                isHeading = true
            ),
            text = state.title
        )
        VSpacer.Large()

        PinFieldLayout(
            modifier = Modifier
                .fillMaxWidth()
                .wrapContentHeight(),
            state = state,
            onPinInput = { quickPin ->
                onEventSend(Event.OnQuickPinEntered(quickPin))
            }
        )
    }

    LaunchedEffect(Unit) {
        effectFlow.onEach { effect ->
            when (effect) {
                is Effect.Navigation -> onNavigationRequested(effect)

                is Effect.CloseBottomSheet -> {
                    coroutineScope.launch {
                        modalBottomSheetState.hide()
                    }.invokeOnCompletion {
                        if (!modalBottomSheetState.isVisible) {
                            onEventSend(Event.BottomSheet.UpdateBottomSheetState(isOpen = false))
                        }
                    }
                }

                is Effect.ShowBottomSheet -> {
                    onEventSend(Event.BottomSheet.UpdateBottomSheetState(isOpen = true))
                }
            }
        }.collect()
    }
}

@Composable
private fun SheetContent(
    onEventSent: (event: Event) -> Unit
) {
    DialogBottomSheet(
        textData = BottomSheetTextDataUi(
            title = stringResource(id = R.string.quick_pin_bottom_sheet_cancel_title),
            message = stringResource(id = R.string.quick_pin_bottom_sheet_cancel_subtitle),
            positiveButtonText = stringResource(id = R.string.quick_pin_bottom_sheet_cancel_primary_button_text),
            negativeButtonText = stringResource(id = R.string.quick_pin_bottom_sheet_cancel_secondary_button_text),
        ),
        onPositiveClick = { onEventSent(Event.BottomSheet.Cancel.ConfirmCancelPressed) },
        onNegativeClick = { onEventSent(Event.BottomSheet.Cancel.DiscardPressed) }
    )
}

@Composable
private fun PinFieldLayout(
    modifier: Modifier = Modifier,
    state: State,
    onPinInput: (String) -> Unit,
) {
    PinHintText(state.subtitle)

    VSpacer.Small()

    OtpTextField(
        modifier = modifier,
        onUpdate = onPinInput,
        otpText = state.pin,
        length = state.quickPinSize,
        hasError = !state.quickPinError.isNullOrEmpty(),
        errorMessage = state.quickPinError,
        visualTransformation = PasswordVisualTransformation(),
        pinWidth = 42.dp,
        focusOnCreate = true,
        enabled = !state.isLockedOut
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@ThemeModePreviews
@Composable
private fun PinScreenCreateEmptyPreview() {
    PreviewTheme {
        Content(
            state = State(
                pinFlow = PinFlow.CREATE,
                pinState = PinValidationState.ENTER,
                title = "Title",
                subtitle = "Subtitle",

                ),
            effectFlow = Channel<Effect>().receiveAsFlow(),
            onEventSend = {},
            onNavigationRequested = {},
            paddingValues = PaddingValues(10.dp),
            coroutineScope = rememberCoroutineScope(),
            modalBottomSheetState = rememberModalBottomSheetState(),
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@ThemeModePreviews
@Composable
private fun PinScreenUpdateEmptyPreview() {
    PreviewTheme {
        Content(
            state = State(
                pinFlow = PinFlow.UPDATE,
                pinState = PinValidationState.ENTER,
                title = "Title",
                subtitle = "Subtitle",

                ),
            effectFlow = Channel<Effect>().receiveAsFlow(),
            onEventSend = {},
            onNavigationRequested = {},
            paddingValues = PaddingValues(10.dp),
            coroutineScope = rememberCoroutineScope(),
            modalBottomSheetState = rememberModalBottomSheetState(),
        )
    }
}

@ThemeModePreviews
@Composable
private fun SheetContentCancelPreview() {
    PreviewTheme {
        SheetContent(
            onEventSent = {}
        )
    }
}
