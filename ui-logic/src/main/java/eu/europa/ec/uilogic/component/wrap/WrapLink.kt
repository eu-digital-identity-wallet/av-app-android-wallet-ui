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

@file:OptIn(ExperimentalMaterial3Api::class)

package eu.europa.ec.uilogic.component.wrap

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.material.ripple.RippleAlpha
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RippleConfiguration
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextLinkStyles
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.style.LineHeightStyle
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.withLink
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.TextUnitType
import androidx.compose.ui.unit.dp
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.uilogic.component.preview.PreviewTheme
import eu.europa.ec.uilogic.component.preview.ThemeModePreviews
import eu.europa.ec.uilogic.component.utils.SIZE_XX_LARGE

data class WrapLinkData(
    @param:StringRes val textId: Int,
    val isExternal: Boolean = false,
)

private val linkSpacing = TextUnit(value = 0.8f, type = TextUnitType.Sp)

// A link is only touchable over its own line boxes, so they have to carry the minimum target size.
private val linkMinTouchTarget = SIZE_XX_LARGE.dp
private val linkLineHeightStyle = LineHeightStyle(
    alignment = LineHeightStyle.Alignment.Center,
    trim = LineHeightStyle.Trim.None,
)

private const val LINK_TAG = "wrap_link"

val BaseRippleConfiguration: RippleConfiguration
    @Composable get() = RippleConfiguration(
        color = MaterialTheme.colorScheme.secondary,
        rippleAlpha = RippleAlpha(0.1f, 0.1f, 0.04f, 0.3f)
    )

@Composable
fun WrapLink(
    data: WrapLinkData,
    modifier: Modifier = Modifier,
    color: Color = MaterialTheme.colorScheme.primary,
    onClick: () -> Unit,
) {
    // A LinkAnnotation, unlike a clickable modifier, reaches the accessibility tree as a
    // ClickableSpan, which is what makes a screen reader announce the text as a link.
    val linkText = buildAnnotatedString {
        withLink(
            LinkAnnotation.Clickable(
                tag = LINK_TAG,
                styles = TextLinkStyles(
                    style = SpanStyle(textDecoration = TextDecoration.Underline)
                ),
                linkInteractionListener = { onClick() }
            )
        ) {
            append(stringResource(id = data.textId))
            if (data.isExternal) {
                withStyle(SpanStyle(textDecoration = TextDecoration.None)) {
                    append(" ↗")
                }
            }
        }
    }

    var lineCount by remember { mutableIntStateOf(1) }
    val baseStyle = MaterialTheme.typography.bodyMedium
    val minLineHeight = with(LocalDensity.current) { (linkMinTouchTarget / lineCount).toSp() }

    val textConfig = TextConfig(
        style = baseStyle.copy(
            letterSpacing = linkSpacing,
            lineHeight = baseStyle.lineHeight.takeIf { it.isSp && it > minLineHeight }
                ?: minLineHeight,
            lineHeightStyle = linkLineHeightStyle,
        ),
        color = color,
    )
    WrapText(
        modifier = modifier.wrapContentWidth(),
        text = linkText,
        textConfig = textConfig,
        onTextLayout = { lineCount = it.lineCount },
    )
}

@Composable
@ThemeModePreviews
private fun WrapLinkPreview() {
    PreviewTheme {
        WrapLink(
            data = WrapLinkData(
                textId = R.string.consent_screen_data_protection_button, isExternal = true
            ), onClick = {})
    }
}
