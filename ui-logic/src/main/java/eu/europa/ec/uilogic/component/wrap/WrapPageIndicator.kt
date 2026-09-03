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

package eu.europa.ec.uilogic.component.wrap

import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.pager.PagerState
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.material3.ripple
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.uilogic.component.preview.PreviewTheme
import eu.europa.ec.uilogic.component.preview.ThemeModePreviews
import eu.europa.ec.uilogic.component.utils.SIZE_SMALL_PLUS
import eu.europa.ec.uilogic.component.utils.SPACING_MEDIUM
import eu.europa.ec.uilogic.util.TestTag
import kotlinx.coroutines.launch

private const val inactiveDotColorAlpha = 0.15f
private val dotRippleRadius = SPACING_MEDIUM.dp + SIZE_SMALL_PLUS.dp / 2

@Composable
fun WrapPageIndicator(pagerState: PagerState, pageTitles: List<String> = emptyList()) {
    val coroutineScope = rememberCoroutineScope()

    Row(
        Modifier
            .wrapContentHeight()
            .fillMaxWidth()
            .selectableGroup(),
        horizontalArrangement = Arrangement.Center
    ) {
        repeat(pagerState.pageCount) { iteration ->
            val isActive = pagerState.currentPage == iteration
            val color = getColor(isActive, inactiveDotColorAlpha)
            val label = pageTitles.getOrNull(iteration)?.let { title ->
                stringResource(
                    id = R.string.accessibility_page_of_total_titled,
                    iteration + 1,
                    pagerState.pageCount,
                    title
                )
            } ?: stringResource(
                id = R.string.accessibility_page_of_total,
                iteration + 1,
                pagerState.pageCount
            )
            Box(
                modifier = Modifier
                    .testTag(TestTag.pageIndicatorDot(iteration))
                    .semantics { contentDescription = label }
                    .minimumInteractiveComponentSize()
                    .selectable(
                        selected = isActive,
                        role = Role.Tab,
                        interactionSource = remember { MutableInteractionSource() },
                        indication = ripple(bounded = false, radius = dotRippleRadius),
                        onClick = {
                            coroutineScope.launch { pagerState.animateScrollToPage(iteration) }
                        },
                    )
                    .padding(SPACING_MEDIUM.dp),
                contentAlignment = Alignment.Center
            ) {
                Box(
                    modifier = Modifier
                        .clip(CircleShape)
                        .background(color)
                        .size(SIZE_SMALL_PLUS.dp)
                )
            }
        }
    }
}

@Composable
@ThemeModePreviews
fun WrapPageIndicatorPreview() {
    PreviewTheme {
        val pagerState = rememberPagerState { 4 }
        WrapPageIndicator(pagerState)
    }
}
