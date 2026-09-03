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

package eu.europa.ec.commonfeature.ui.document_success

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import eu.europa.ec.commonfeature.util.TestTag
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.uilogic.component.AppIconAndTextDataUi
import eu.europa.ec.uilogic.component.ListItemDataUi
import eu.europa.ec.uilogic.component.ListItemMainContentDataUi
import eu.europa.ec.uilogic.component.RelyingPartyDataUi
import eu.europa.ec.uilogic.component.content.ContentHeader
import eu.europa.ec.uilogic.component.content.ContentHeaderConfig
import eu.europa.ec.uilogic.component.content.ContentScreen
import eu.europa.ec.uilogic.component.content.ScreenNavigateAction
import eu.europa.ec.uilogic.component.preview.PreviewTheme
import eu.europa.ec.uilogic.component.preview.ThemeModePreviews
import eu.europa.ec.uilogic.component.utils.OneTimeLaunchedEffect
import eu.europa.ec.uilogic.component.utils.SPACING_MEDIUM
import eu.europa.ec.uilogic.component.utils.SPACING_SMALL
import eu.europa.ec.uilogic.component.wrap.ButtonConfig
import eu.europa.ec.uilogic.component.wrap.ButtonType
import eu.europa.ec.uilogic.component.wrap.ExpandableListItemUi
import eu.europa.ec.uilogic.component.wrap.StickyBottomConfig
import eu.europa.ec.uilogic.component.wrap.StickyBottomType
import eu.europa.ec.uilogic.component.wrap.WrapExpandableListItem
import eu.europa.ec.uilogic.component.wrap.WrapStickyBottomContent
import eu.europa.ec.uilogic.extension.cacheDeepLink
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.onEach

@Composable
fun DocumentSuccessScreen(
    navController: NavController,
    viewModel: DocumentSuccessViewModel,
) {
    val context = LocalContext.current
    val state: State by viewModel.viewState.collectAsStateWithLifecycle()

    ContentScreen(
        isLoading = false,
        stickyBottom = { paddingValues ->
            WrapStickyBottomContent(
                modifier = Modifier
                    .testTag(TestTag.DocumentSuccessScreen.BUTTON)
                    .fillMaxWidth()
                    .padding(paddingValues),
                stickyBottomConfig = StickyBottomConfig(
                    type = StickyBottomType.OneButton(
                        config = ButtonConfig(
                            type = ButtonType.SECONDARY,
                            enabled = !state.isLoading,
                            onClick = { viewModel.setEvent(Event.StickyButtonPressed) }
                        )
                    )
                )
            ) {
                Text(text = stringResource(R.string.document_success_sticky_button_text))
            }
        },
        navigatableAction = ScreenNavigateAction.NONE,
    ) { paddingValues ->
        Content(
            state = state,
            effectFlow = viewModel.effect,
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

    OneTimeLaunchedEffect {
        viewModel.setEvent(Event.DoWork)
    }
}

@Composable
private fun Content(
    state: State,
    effectFlow: Flow<Effect>,
    onNavigationRequested: (Effect.Navigation) -> Unit,
    paddingValues: PaddingValues,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(paddingValues)
            .verticalScroll(rememberScrollState())
    ) {
        ContentHeader(
            modifier = Modifier.fillMaxWidth(),
            config = state.headerConfig,
            descriptionTestTag = TestTag.DocumentSuccessScreen.CONTENT_HEADER_DESCRIPTION,
        )

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = SPACING_SMALL.dp),
            verticalArrangement = Arrangement.spacedBy(SPACING_MEDIUM.dp)
        ) {
            state.items.forEachIndexed { index, successItem ->
                WrapExpandableListItem(
                    modifier = Modifier
                        .testTag(TestTag.DocumentSuccessScreen.successDocument(index = index))
                        .fillMaxWidth(),
                    header = successItem.header,
                    data = successItem.nestedItems,
                    onItemClick = null,
                    onExpandedChange = { },
                    isExpanded = true,
                    throttleClicks = false,
                    hideSensitiveContent = false,
                    collapsedMainContentVerticalPadding = SPACING_MEDIUM.dp,
                    expandedMainContentVerticalPadding = SPACING_MEDIUM.dp,
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.tertiary,
                    )
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

@ThemeModePreviews
@Composable
fun DocumentSuccessScreenPreview() {
    PreviewTheme {
        Content(
            state = State(
                isLoading = false,
                headerConfig = ContentHeaderConfig(
                    appIconAndTextData = AppIconAndTextDataUi(),
                    description = null,
                    descriptionTextConfig = null,
                    mainText = stringResource(R.string.issuance_success_header_description),
                    mainTextConfig = null,
                    relyingPartyData = RelyingPartyDataUi(
                        logo = null,
                        isVerified = true,
                        name = "Test Issuer",
                        nameTextConfig = null,
                        description = null,
                        descriptionTextConfig = null
                    )
                ),
                items = listOf(
                    ExpandableListItemUi.NestedListItem(
                        header = ListItemDataUi(
                            itemId = "1",
                            mainContentData = ListItemMainContentDataUi.Text(
                                text = "True"
                            ),
                            overlineText = "Age over 18",
                            leadingContentData = null,
                            trailingContentData = null
                        ),
                        nestedItems = emptyList(),
                        isExpanded = true
                    )
                )
            ),
            effectFlow = flowOf(),
            onNavigationRequested = {},
            paddingValues = PaddingValues(16.dp)
        )
    }
}
