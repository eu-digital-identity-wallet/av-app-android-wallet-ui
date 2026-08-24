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

package eu.europa.ec.onboardingfeature.ui.enrollment

import android.content.Context
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import eu.europa.ec.corelogic.util.CoreActions
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.uilogic.component.AppIcons
import eu.europa.ec.uilogic.component.TopStepBar
import eu.europa.ec.uilogic.component.content.BroadcastAction
import eu.europa.ec.uilogic.component.content.ContentScreen
import eu.europa.ec.uilogic.component.content.ScreenNavigateAction
import eu.europa.ec.uilogic.component.preview.PreviewTheme
import eu.europa.ec.uilogic.component.preview.ThemeModePreviews
import eu.europa.ec.uilogic.component.utils.HSpacer
import eu.europa.ec.uilogic.component.utils.LifecycleEffect
import eu.europa.ec.uilogic.component.utils.SPACING_MEDIUM
import eu.europa.ec.uilogic.component.utils.VSpacer
import eu.europa.ec.uilogic.component.wrap.TextConfig
import eu.europa.ec.uilogic.component.wrap.WrapIcon
import eu.europa.ec.uilogic.component.wrap.WrapText
import eu.europa.ec.uilogic.extension.finish
import eu.europa.ec.uilogic.extension.getPendingDeepLink
import eu.europa.ec.uilogic.navigation.OnboardingScreens
import eu.europa.ec.uilogic.navigation.helper.handleDeepLinkAction
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.onEach

@Composable
fun EnrollmentScreen(
    hostNavController: NavController,
    viewModel: EnrollmentViewModel,
) {
    val context = LocalContext.current
    val state by viewModel.viewState.collectAsStateWithLifecycle()

    ContentScreen(
        isLoading = state.isLoading,
        navigatableAction = ScreenNavigateAction.NONE,
        onBack = { viewModel.setEvent(Event.Pop) },
        contentErrorConfig = state.error,
        broadcastAction = BroadcastAction(
            intentFilters = listOf(
                CoreActions.VCI_RESUME_ACTION,
                CoreActions.VCI_DYNAMIC_PRESENTATION
            ),
            callback = {
                when (it?.action) {
                    CoreActions.VCI_RESUME_ACTION -> it.extras?.getString("uri")?.let { link ->
                        viewModel.setEvent(Event.OnResumeIssuance(link))
                    }

                    CoreActions.VCI_DYNAMIC_PRESENTATION -> it.extras?.getString("uri")
                        ?.let { link ->
                            viewModel.setEvent(Event.OnDynamicPresentation(link))
                        }
                }
            }
        )
    ) { paddingValues ->
        Content(
            paddingValues = paddingValues,
            onMethodSelected = { method ->
                viewModel.setEvent(Event.SelectEnrollmentMethod(method, context))
            },
            showStepBar = state.isOnboarding,
            availableMethods = state.availableEnrollmentMethods
        )
    }

    LaunchedEffect(Unit) {
        viewModel.effect.onEach { effect ->
            handleEffect(effect, hostNavController, context)
        }.collect()
    }

    LifecycleEffect(
        lifecycleOwner = LocalLifecycleOwner.current,
        lifecycleEvent = Lifecycle.Event.ON_PAUSE
    ) {
        viewModel.setEvent(Event.OnPause)
    }

    LifecycleEffect(
        lifecycleOwner = LocalLifecycleOwner.current,
        lifecycleEvent = Lifecycle.Event.ON_RESUME
    ) {
        viewModel.setEvent(Event.Init(context.getPendingDeepLink()))
    }
}

private fun handleEffect(
    effect: Effect,
    hostNavController: NavController,
    context: Context,
) {
    when (effect) {
        is Effect.Navigation.SwitchScreen -> {
            hostNavController.navigate(effect.screenRoute) {
                popUpTo(OnboardingScreens.Enrollment.screenRoute) {
                    inclusive = effect.inclusive
                }
            }
        }

        is Effect.Navigation.Finish -> context.finish()
        is Effect.Navigation.OpenDeepLinkAction -> handleDeepLinkAction(
            hostNavController,
            effect.deepLinkUri,
            effect.arguments
        )
    }
}

@Composable
private fun Content(
    paddingValues: PaddingValues,
    onMethodSelected: (EnrollmentMethod) -> Unit,
    showStepBar: Boolean = true,
    availableMethods: List<EnrollmentMethod> = EnrollmentMethod.entries,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(paddingValues)
            .verticalScroll(rememberScrollState())
    ) {
        if (showStepBar) {
            TopStepBar(currentStep = 3)
        }
        VSpacer.ExtraLarge()

        WrapText(
            text = stringResource(R.string.onboarding_verification_title),
            textConfig = TextConfig(
                style = MaterialTheme.typography.titleLarge,
                maxLines = Int.MAX_VALUE,
                isHeading = true
            ),
        )
        VSpacer.Large()

        WrapText(
            text = stringResource(R.string.onboarding_verification_description),
            textConfig = TextConfig(
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 6
            ),
        )

        VSpacer.Large()

        Column(
            modifier = Modifier.fillMaxWidth(),
        ) {
            availableMethods.forEach { method ->
                EnrollmentMethodCard(
                    method = method,
                    onClick = { onMethodSelected(method) }
                )
                VSpacer.Medium()
            }
        }
    }
}

@Composable
private fun EnrollmentMethodCard(
    method: EnrollmentMethod,
    onClick: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        onClick = onClick,
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer,
            contentColor = MaterialTheme.colorScheme.onPrimaryContainer
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = 1.dp
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(SPACING_MEDIUM.dp),
        ) {
            WrapIcon(
                modifier = Modifier.size(24.dp),
                iconData = when (method) {
                    EnrollmentMethod.NATIONAL_ID -> AppIcons.NationalEID
                    EnrollmentMethod.PASSPORT_ID_CARD -> AppIcons.Id
                    EnrollmentMethod.TOKEN_QR -> AppIcons.QrScanner
                },
                customTint = MaterialTheme.colorScheme.primary
            )
            HSpacer.Small()
            Column {
                WrapText(
                    text = getMethodTitle(method),
                    textConfig = TextConfig(
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                )
                VSpacer.ExtraSmall()
                WrapText(
                    text = getMethodDescription(method),
                    textConfig = TextConfig(
                        style = MaterialTheme.typography.bodyMedium,
                    )
                )
            }
        }
    }
}

@Composable
private fun getMethodTitle(method: EnrollmentMethod): String {
    return stringResource(
        when (method) {
            EnrollmentMethod.NATIONAL_ID -> R.string.onboarding_verification_national_id
            EnrollmentMethod.PASSPORT_ID_CARD -> R.string.onboarding_verification_passport_id_card
            EnrollmentMethod.TOKEN_QR -> R.string.onboarding_verification_token_qr
        }
    )
}

@Composable
private fun getMethodDescription(method: EnrollmentMethod): String {
    return stringResource(
        when (method) {
            EnrollmentMethod.NATIONAL_ID -> R.string.onboarding_verification_national_id_description
            EnrollmentMethod.PASSPORT_ID_CARD -> R.string.onboarding_verification_passport_id_card_description
            EnrollmentMethod.TOKEN_QR -> R.string.onboarding_verification_token_qr_description
        }
    )
}

@ThemeModePreviews
@Composable
private fun EnrollmentScreenPreview() {
    PreviewTheme {
        ContentScreen(
            isLoading = false,
            navigatableAction = ScreenNavigateAction.NONE,
            onBack = {},
        ) { paddingValues ->
            Content(
                paddingValues = paddingValues,
                onMethodSelected = {},
                showStepBar = true
            )
        }
    }
}

@ThemeModePreviews
@Composable
private fun EnrollmentScreenWithoutStepBarPreview() {
    PreviewTheme {
        ContentScreen(
            isLoading = false,
            navigatableAction = ScreenNavigateAction.NONE,
            onBack = {},
        ) { paddingValues ->
            Content(
                paddingValues = paddingValues,
                onMethodSelected = {},
                showStepBar = false
            )
        }
    }
}