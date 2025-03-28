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

package eu.europa.ec.onboardingfeature.ui.welcome

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.PagerScope
import androidx.compose.foundation.pager.PagerState
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import eu.europa.ec.onboardingfeature.ui.components.TopStepBar
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.uilogic.component.AppIcons
import eu.europa.ec.uilogic.component.IconData
import eu.europa.ec.uilogic.component.content.ContentScreen
import eu.europa.ec.uilogic.component.content.ScreenNavigateAction
import eu.europa.ec.uilogic.component.preview.PreviewTheme
import eu.europa.ec.uilogic.component.preview.ThemeModePreviews
import eu.europa.ec.uilogic.component.utils.SIZE_XXX_LARGE
import eu.europa.ec.uilogic.component.utils.SPACING_MEDIUM
import eu.europa.ec.uilogic.component.utils.VSpacer
import eu.europa.ec.uilogic.component.wrap.ButtonConfig
import eu.europa.ec.uilogic.component.wrap.ButtonType
import eu.europa.ec.uilogic.component.wrap.StickyBottomConfig
import eu.europa.ec.uilogic.component.wrap.StickyBottomType
import eu.europa.ec.uilogic.component.wrap.TextConfig
import eu.europa.ec.uilogic.component.wrap.WrapImage
import eu.europa.ec.uilogic.component.wrap.WrapPageIndicator
import eu.europa.ec.uilogic.component.wrap.WrapStickyBottomContent
import eu.europa.ec.uilogic.component.wrap.WrapText
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
fun WelcomeScreen(navController: NavController, viewModel: WelcomeViewModel) {
    val state: State by viewModel.viewState.collectAsStateWithLifecycle()
    val pagerState = rememberPagerState { state.pages.size }

    ContentScreen(isLoading = false,
        navigatableAction = ScreenNavigateAction.NONE,
        onBack = { },
        stickyBottom = { paddingValues ->
            WrapStickyBottomContent(
                stickyBottomModifier = Modifier
                    .fillMaxWidth()
                    .padding(paddingValues),
                stickyBottomConfig = StickyBottomConfig(
                    type = StickyBottomType.OneButton(
                        config = ButtonConfig(type = ButtonType.PRIMARY,
                            onClick = { viewModel.setEvent(Event.GoNext) })
                    ), showDivider = false
                )
            ) {
                Text(
                    text = stringResource(
                        viewModel.getNextButtonResId(
                            pagerState.currentPage, pagerState.pageCount
                        )
                    )
                )
            }
        }) { _ ->
        Content(
            pages = state.pages, pagerState = pagerState,
            effectFlow = viewModel.effect,
            onNavigationRequested = { navigationEffect ->
                handleNavigationEffect(navigationEffect, navController)
            },
        )
    }
}

@Composable
private fun Content(
    pages: List<SinglePageConfig>,
    pagerState: PagerState,
    effectFlow: Flow<Effect>,
    onNavigationRequested: (Effect.Navigation) -> Unit,
) {
    Column {
        TopStepBar(0)
        VSpacer.ExtraLarge()
        WelcomePager(pagerState = pagerState, pages = pages)
        WrapPageIndicator(pagerState)
    }

    LaunchedEffect(Unit) {
        effectFlow.onEach { effect ->
            when (effect) {
                is Effect.Navigation.SwitchScreen -> onNavigationRequested(effect)
            }
        }.collect()
    }
}

@Composable
private fun WelcomePager(pagerState: PagerState, pages: List<SinglePageConfig>) {
    HorizontalPager(
        state = pagerState,
        modifier = Modifier
            .fillMaxWidth()
            .wrapContentHeight()
            .defaultMinSize(minHeight = 190.dp),
        pageContent = SinglePage(pages)
    )
}

private fun handleNavigationEffect(
    navigationEffect: Effect.Navigation, navController: NavController
) {
    when (navigationEffect) {
        is Effect.Navigation.SwitchScreen -> {
            navController.navigate(navigationEffect.screenRoute)
        }
    }
}

data class SinglePageConfig(val title: Int, val description: Int, val icon: IconData)

@Composable
private fun SinglePage(
    pages: List<SinglePageConfig>
): @Composable (PagerScope.(page: Int) -> Unit) = { page ->
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier
            .fillMaxWidth()
            .wrapContentHeight()
            .defaultMinSize(minHeight = 180.dp)
            .padding(horizontal = SPACING_MEDIUM.dp)
    ) {
        WrapImage(
            iconData = pages[page].icon,
            contentScale = ContentScale.FillHeight,
            modifier = Modifier
                .heightIn(max = SIZE_XXX_LARGE.dp)
                .fillMaxHeight()
                .wrapContentHeight()

        )
        VSpacer.Large()
        WrapText(
            modifier = Modifier.fillMaxWidth(),
            text = stringResource(id = pages[page].title),
            textConfig = TextConfig(
                style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Start
            )
        )
        VSpacer.Large()
        WrapText(
            modifier = Modifier.fillMaxWidth(),
            text = stringResource(id = pages[page].description),
            textConfig = TextConfig(
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Start,
                maxLines = Int.MAX_VALUE
            )
        )
    }
}

@ThemeModePreviews
@Composable
private fun WelcomeScreenPreview() {
    PreviewTheme {
        val pages = listOf(
            SinglePageConfig(
                title = R.string.welcome_title_1,
                description = R.string.welcome_page_1,
                icon = AppIcons.PresentDocumentInPerson
            ), SinglePageConfig(
                title = R.string.welcome_title_2,
                description = R.string.welcome_page_2,
                icon = AppIcons.WalletActivated
            ), SinglePageConfig(
                title = R.string.welcome_title_3,
                description = R.string.welcome_page_3,
                icon = AppIcons.WalletSecured
            )
        )
        val pagerState = rememberPagerState { pages.size }
        Content(
            pages = pages, pagerState = pagerState,
            effectFlow = Channel<Effect>().receiveAsFlow(),
            onNavigationRequested = {},
        )
    }
}