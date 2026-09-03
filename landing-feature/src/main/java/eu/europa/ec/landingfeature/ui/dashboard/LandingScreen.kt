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

package eu.europa.ec.landingfeature.ui.dashboard

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.wrapContentSize
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Badge
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FabPosition
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.isTraversalGroup
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.traversalIndex
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.zIndex
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import eu.europa.ec.commonfeature.navigation.helper.handleIntentAction
import eu.europa.ec.landingfeature.model.AgeCredentialCardUi
import eu.europa.ec.landingfeature.model.RemainingAccessesUi
import eu.europa.ec.landingfeature.util.TestTag
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.uilogic.component.AppIcons
import eu.europa.ec.uilogic.component.ListItemDataUi
import eu.europa.ec.uilogic.component.ListItemMainContentDataUi
import eu.europa.ec.uilogic.component.content.ContentScreen
import eu.europa.ec.uilogic.component.content.ScreenNavigateAction
import eu.europa.ec.uilogic.component.preview.PreviewTheme
import eu.europa.ec.uilogic.component.preview.ThemeModePreviews
import eu.europa.ec.uilogic.component.utils.DEFAULT_BIG_ICON_SIZE
import eu.europa.ec.uilogic.component.utils.HSpacer
import eu.europa.ec.uilogic.component.utils.LifecycleEffect
import eu.europa.ec.uilogic.component.utils.SPACING_EXTRA_SMALL
import eu.europa.ec.uilogic.component.utils.SPACING_LARGE
import eu.europa.ec.uilogic.component.utils.SPACING_SMALL
import eu.europa.ec.uilogic.component.utils.VSpacer
import eu.europa.ec.uilogic.component.wrap.ExpandableListItemUi
import eu.europa.ec.uilogic.component.wrap.TextConfig
import eu.europa.ec.uilogic.component.wrap.WrapIcon
import eu.europa.ec.uilogic.component.wrap.WrapIconButton
import eu.europa.ec.uilogic.component.wrap.WrapImage
import eu.europa.ec.uilogic.component.wrap.WrapListItems
import eu.europa.ec.uilogic.component.wrap.WrapText
import eu.europa.ec.uilogic.extension.finish
import eu.europa.ec.uilogic.extension.getPendingDeepLink
import eu.europa.ec.uilogic.extension.getPendingIntentAction
import eu.europa.ec.uilogic.navigation.helper.handleDeepLinkAction
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.onEach

@Composable
fun LandingScreen(controller: NavController, viewModel: LandingViewModel) {

    val context = LocalContext.current
    val state: State by viewModel.viewState.collectAsStateWithLifecycle()

    ContentScreen(
        isLoading = state.isLoading,
        navigatableAction = ScreenNavigateAction.NONE,
        onBack = { context.finish() },
        topBar = { TopBar(onEventSend = { viewModel.setEvent(it) }) },
        fab = { ScanButton(onEventSend = { viewModel.setEvent(it) }) },
        fabPosition = FabPosition.Center
    ) { paddingValues ->
        Content(
            paddingValues = paddingValues,
            documentClaims = state.documentClaims,
            credentialCard = state.credentialCard,
            onAddCredential = { viewModel.setEvent(Event.AddCredentials) }
        )
    }

    LifecycleEffect(
        lifecycleOwner = LocalLifecycleOwner.current,
        lifecycleEvent = Lifecycle.Event.ON_RESUME
    ) {
        viewModel.setEvent(
            Event.Init(
                deepLinkUri = context.getPendingDeepLink(),
                intentAction = context.getPendingIntentAction()
            )
        )
    }

    LaunchedEffect(Unit) {
        viewModel.effect.onEach { effect ->
            when (effect) {
                is Effect.Navigation -> handleNavigationEffect(effect, controller, context)
            }
        }.collect()
    }
}

@Composable
internal fun ScanButton(onEventSend: (Event) -> Unit) {
    val scanQrLabel = stringResource(R.string.generic_scan_qr)

    Column(modifier = Modifier.wrapContentSize()) {
        FloatingActionButton(
            modifier = Modifier
                .align(Alignment.CenterHorizontally)
                .testTag(TestTag.LandingScreen.SCAN_BUTTON)
                .semantics(mergeDescendants = true) { contentDescription = scanQrLabel },
            onClick = { onEventSend(Event.GoToScanQR) },
            containerColor = MaterialTheme.colorScheme.primary,
            contentColor = MaterialTheme.colorScheme.onPrimary,
            shape = CircleShape,
        ) {
            WrapIcon(
                modifier = Modifier
                    .padding(SPACING_LARGE.dp)
                    .clearAndSetSemantics { },
                iconData = AppIcons.QrScanner
            )
        }

        VSpacer.ExtraSmall()
        WrapText(text = stringResource(R.string.landing_screen_primary_button_label_scan),
            textConfig = TextConfig(
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            ),
            modifier = Modifier
                .align(Alignment.CenterHorizontally)
                .clearAndSetSemantics { }
        )
    }
}

private fun handleNavigationEffect(
    navigationEffect: Effect.Navigation,
    navController: NavController,
    context: Context,
) {
    when (navigationEffect) {
        is Effect.Navigation.Pop -> context.finish()
        is Effect.Navigation.SwitchScreen -> {
            navController.navigate(navigationEffect.screenRoute) {
                popUpTo(navigationEffect.popUpToScreenRoute) {
                    inclusive = navigationEffect.inclusive
                }
            }
        }

        is Effect.Navigation.OpenDeepLinkAction -> {
            handleDeepLinkAction(
                navController,
                navigationEffect.deepLinkUri,
                navigationEffect.arguments
            )
        }

        is Effect.Navigation.OpenIntentAction -> {
            handleIntentAction(
                navController,
                navigationEffect.intentAction
            )
        }
    }
}

@Composable
private fun TopBar(onEventSend: (Event) -> Unit) = Box(
    modifier = Modifier
        .fillMaxWidth()
        .padding(
            end = SPACING_SMALL.dp,
            bottom = SPACING_LARGE.dp,
            top = DEFAULT_BIG_ICON_SIZE.dp
        )
) {
    WrapImage(
        modifier = Modifier
            .height(40.dp)
            .align(Alignment.Center),
        iconData = AppIcons.LogoPlain,
        contentScale = ContentScale.Fit,
    )

    WrapIconButton(
        modifier = Modifier.align(Alignment.CenterEnd),
        iconData = AppIcons.Settings,
        customTint = MaterialTheme.colorScheme.onSurfaceVariant,
    ) {
        onEventSend(Event.GoToSettings)
    }
}

@Composable
private fun Content(
    paddingValues: PaddingValues,
    documentClaims: List<ExpandableListItemUi>?,
    credentialCard: AgeCredentialCardUi,
    onAddCredential: () -> Unit,
) {

    Column(modifier = Modifier
        .fillMaxSize()
        .padding(paddingValues)
        .verticalScroll(rememberScrollState())) {

        WrapText(
            text = stringResource(R.string.landing_screen_title),
            textConfig = TextConfig(
                style = MaterialTheme.typography.headlineLarge,
                isHeading = true,
            )
        )

        VSpacer.Large()
        WrapText(
            text = stringResource(R.string.landing_screen_subtitle),
            textConfig = TextConfig(
                style = MaterialTheme.typography.bodyLarge,
                maxLines = Int.MAX_VALUE
            )
        )
        VSpacer.ExtraLarge()

        AgeVerificationCard(
            credentialCard = credentialCard,
            onAddCredential = onAddCredential,
        )

        if (!documentClaims.isNullOrEmpty()) {
            CredentialDetails(documentClaims)
        }

        VSpacer.XXLarge()
    }
}

@Composable
private fun CredentialDetails(documentClaims: List<ExpandableListItemUi>) {
    VSpacer.ExtraLarge()

    WrapText(
        text = stringResource(R.string.landing_screen_credential_details),
        textConfig = TextConfig(
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.primary,
            textAlign = TextAlign.Start,
            isHeading = true,
        )
    )

    VSpacer.ExtraSmall()

    WrapListItems(
        modifier = Modifier.fillMaxWidth(),
        items = documentClaims,
        onItemClick = null,
        mainContentVerticalPadding = 16.dp,
        addDivider = true,
        onExpandedChange = {}
    )
}

@Composable
private fun AgeOverBadge(age: Int) {
    Box(modifier = Modifier.size(width = 64.dp, height = 61.dp)) {
        Box(
            modifier = Modifier
                .size(53.dp)
                .align(Alignment.BottomStart)
                .clip(CircleShape)
                .background(Color(0xFF9FB5EA)),
            contentAlignment = Alignment.Center
        ) {
            WrapText(
                text = "$age+",
                textConfig = TextConfig(
                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                    color = Color(0xFF003399),
                    maxLines = 1,
                )
            )
        }
        Box(
            modifier = Modifier
                .size(26.dp)
                .align(Alignment.TopEnd)
                .clip(
                    RoundedCornerShape(
                        topStart = 13.dp,
                        topEnd = 13.dp,
                        bottomEnd = 13.dp,
                        bottomStart = 0.dp
                    )
                )
                .background(Color(0xFF1544C5)),
            contentAlignment = Alignment.Center
        ) {
            WrapIcon(
                iconData = AppIcons.Check,
                modifier = Modifier.size(14.dp),
                customTint = Color.White,
            )
        }
    }
}

@Composable
private fun AgeVerificationCard(
    credentialCard: AgeCredentialCardUi,
    onAddCredential: () -> Unit,
) {
    // The card and its badge are one block to a screen reader: the card describes the proof of
    // age as a whole, then the badge follows with how many accesses are left.
    Box(modifier = Modifier.semantics { isTraversalGroup = true }) {
        credentialCard.remainingAccesses?.let { remainingAccesses ->
            RemainingAccessesBadge(remainingAccesses, onAddCredential)
        }

        Card(
            modifier = Modifier
                .height(130.dp)
                .fillMaxWidth()
                .testTag(TestTag.LandingScreen.CREDENTIAL_CARD)
                .clearAndSetSemantics {
                    traversalIndex = 0f
                    contentDescription = credentialCard.accessibilityLabel
                },
            colors = CardDefaults.cardColors(
                containerColor = Color(0xFFEBF1FD),
            ),
            elevation = CardDefaults.cardElevation(
                defaultElevation = 4.dp
            )
        ) {
            Row(
                modifier = Modifier.fillMaxWidth()
            ) {
                // First stripe
                Box(
                    modifier = Modifier
                        .width(9.dp)
                        .fillMaxHeight()
                        .background(MaterialTheme.colorScheme.primary)
                )
                HSpacer.ExtraSmall()
                // Second stripe
                Box(
                    modifier = Modifier
                        .width(5.dp)
                        .fillMaxHeight()
                        .background(MaterialTheme.colorScheme.primary)
                )
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(SPACING_SMALL.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.Top,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        val labelSmallTextConfig = TextConfig(
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Row(
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            WrapImage(
                                modifier = Modifier
                                    .width(40.dp),
                                iconData = AppIcons.EuFlag,
                                contentScale = ContentScale.Fit
                            )
                            HSpacer.ExtraSmall()
                            WrapText(
                                text = stringResource(R.string.landing_screen_card_eu_title),
                                textConfig = labelSmallTextConfig
                            )
                        }
                    }
                    VSpacer.Large()
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Absolute.Center
                    ) {
                        credentialCard.ageThreshold?.let { ageThreshold ->
                            AgeOverBadge(age = ageThreshold)
                            HSpacer.Small()
                        }
                        WrapText(
                            text = stringResource(R.string.landing_screen_card_age_verification),
                            textConfig = TextConfig(
                                style = MaterialTheme.typography.titleLarge,
                                color = MaterialTheme.colorScheme.primary
                            )
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun BoxScope.RemainingAccessesBadge(
    remainingAccesses: RemainingAccessesUi,
    onAddCredential: () -> Unit,
) {
    // Only the depleted badge leads anywhere, so only then is it offered as a button.
    val actionModifier = if (remainingAccesses.isDepleted) {
        Modifier.clickable(role = Role.Button) { onAddCredential() }
    } else {
        Modifier
    }

    Badge(
        modifier = Modifier
            .align(Alignment.TopEnd)
            .padding(top = SPACING_SMALL.dp, end = SPACING_SMALL.dp)
            .zIndex(1f)
            .testTag(TestTag.LandingScreen.REMAINING_ACCESSES)
            .then(actionModifier)
            .semantics(mergeDescendants = true) {
                traversalIndex = 1f
                contentDescription = remainingAccesses.accessibilityLabel
            },
        containerColor = if (remainingAccesses.isDepleted) {
            MaterialTheme.colorScheme.error
        } else {
            MaterialTheme.colorScheme.primary
        },
    ) {
        WrapText(
            modifier = Modifier.padding(SPACING_EXTRA_SMALL.dp),
            text = remainingAccesses.label,
            textConfig = TextConfig(
                style = MaterialTheme.typography.labelSmall,
                color = if (remainingAccesses.isDepleted) {
                    MaterialTheme.colorScheme.onError
                } else {
                    MaterialTheme.colorScheme.onPrimary
                }
            )
        )
    }
}

@ThemeModePreviews
@Composable
private fun LandingScreenPreview() {
    PreviewTheme {
        ContentScreen(
            isLoading = false,
            navigatableAction = ScreenNavigateAction.NONE,
            onBack = { },
            topBar = {
                TopBar(
                    onEventSend = { }
                )
            },
        ) { paddingValues ->
            Content(
                documentClaims = listOf(
                    ExpandableListItemUi.SingleListItem(
                        header = ListItemDataUi(
                            itemId = "0",
                            overlineText = "Age over 18",
                            mainContentData = ListItemMainContentDataUi.Text(text = "True"),
                        )
                    ),
                    ExpandableListItemUi.SingleListItem(
                        header = ListItemDataUi(
                            itemId = "1",
                            overlineText = "Expiration Date",
                            mainContentData = ListItemMainContentDataUi.Text(text = "30/12/2025"),
                        )
                    )
                ),
                paddingValues = paddingValues,
                credentialCard = AgeCredentialCardUi(
                    ageThreshold = 18,
                    accessibilityLabel = "European Union proof of age, confirming that you are over 18",
                    remainingAccesses = RemainingAccessesUi(
                        label = "3 left",
                        accessibilityLabel = "3 proofs of age left",
                        isDepleted = false,
                    ),
                ),
                onAddCredential = { }
            )
        }
    }
}