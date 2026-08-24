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

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.TextMeasurer
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.uilogic.component.preview.PreviewTheme
import eu.europa.ec.uilogic.component.preview.ThemeModePreviews
import eu.europa.ec.uilogic.component.utils.SIZE_EXTRA_SMALL
import eu.europa.ec.uilogic.component.utils.SPACING_EXTRA_SMALL
import eu.europa.ec.uilogic.component.utils.SPACING_LARGE
import eu.europa.ec.uilogic.component.utils.SPACING_SMALL_PLUS
import eu.europa.ec.uilogic.component.utils.measureTextWidthInPx
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

private val horizontalLabelPaddingDp = SPACING_SMALL_PLUS.dp
private val paddingValues = PaddingValues(
    horizontal = horizontalLabelPaddingDp, vertical = SPACING_EXTRA_SMALL.dp
)
private val labelTextStyle: TextStyle
    @Composable
    get() = MaterialTheme.typography.titleSmall

private const val inactiveTextColorAlpha = 0.35f

@Composable
fun WrapStepBar(currentStep: Int, steps: List<String>, modifier: Modifier = Modifier) {
    val textMeasurer = rememberTextMeasurer()
    val listState = rememberLazyListState()
    val coroutineScope = rememberCoroutineScope()

    val startIndex = calculateStartIndex(currentStep, steps, textMeasurer)

    ElevatedCard(
        modifier = modifier.fillMaxWidth(),
        shape = buttonsShape,
        elevation = CardDefaults.elevatedCardElevation(defaultElevation = SIZE_EXTRA_SMALL.dp),
        colors = CardDefaults.elevatedCardColors(
            MaterialTheme.colorScheme.background,
        ),
    ) {
        LazyRow(
            state = listState,
            modifier = Modifier
                .fillMaxWidth()
                .clipToBounds(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceEvenly,
            userScrollEnabled = true
        ) {
            itemsIndexed(steps) { index, text ->
                Label(
                    text = text,
                    index = index,
                    currentStep = currentStep,
                    totalSteps = steps.size,
                )
            }
        }
    }

    ScrollToTheStartIndex(startIndex, coroutineScope, listState)
}

@Composable
private fun ScrollToTheStartIndex(
    startIndex: Int,
    coroutineScope: CoroutineScope,
    listState: LazyListState
) {
    LaunchedEffect(startIndex) {
        coroutineScope.launch {
            listState.scrollToItem(startIndex)
        }
    }
}

@Composable
private fun calculateStartIndex(
    currentStep: Int,
    steps: List<String>,
    textMeasurer: TextMeasurer
): Int {
    if (currentStep == 0) {
        return 0
    } else if (currentStep < steps.size - 2) {
        return currentStep - 1
    }

    // only for the last two steps we calculate the start index in a fancy way
    // taking into account the screen and font size
    val startIndex = calculateStartIndexForTrailingItems(currentStep, steps, textMeasurer)

    return startIndex
}

@Composable
private fun calculateStartIndexForTrailingItems(
    currentStep: Int,
    steps: List<String>,
    textMeasurer: TextMeasurer
): Int {
    val density = LocalDensity.current
    val fontScale = density.fontScale
    val configuration = LocalConfiguration.current
    val rowWidthPx = with(density) { (configuration.screenWidthDp - 2 * SPACING_LARGE).dp.toPx() }
    val paddingWidthPx = with(density) { 2 * horizontalLabelPaddingDp.toPx() }

    var totalWidth = 0f
    var startIndex = currentStep
    for (i in steps.size - 1 downTo 0) {
        val textWidth = measureTextWidthInPx(steps[i], textMeasurer, labelTextStyle, fontScale)
        val stepWidth = textWidth + paddingWidthPx
        if (totalWidth + stepWidth > rowWidthPx) {
            break
        }
        totalWidth += stepWidth
        startIndex = i
    }
    return startIndex
}



@Composable
private fun Label(text: String, index: Int, currentStep: Int, totalSteps: Int) {
    val isActive = index == currentStep
    val textColor = getColor(isActive, inactiveTextColorAlpha)
    val label = stringResource(
        id = R.string.accessibility_step_of_total,
        index + 1,
        totalSteps,
        text
    )
    val currentStepState = stringResource(id = R.string.accessibility_step_current)

    Text(
        modifier = Modifier
            .padding(paddingValues)
            .semantics {
                selected = isActive
                contentDescription = label
                if (isActive) {
                    stateDescription = currentStepState
                }
            },
        text = text,
        color = textColor,
        style = labelTextStyle,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
    )
}

@Composable
fun getColor(isActive: Boolean, inactiveAlpha: Float) =
    if (isActive) MaterialTheme.colorScheme.primary
    else MaterialTheme.colorScheme.onSurface.copy(alpha = inactiveAlpha)


@Composable
@ThemeModePreviews
fun StartupProgressBarPreview() {
    PreviewTheme {
        WrapStepBar(
            currentStep = 5,
            steps = listOf("Step 1", "Step 2", "Step 3", "Step 4", "Step 5", "Step 6")
        )
    }
}


