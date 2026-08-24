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

import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.PreviewParameter
import eu.europa.ec.uilogic.component.preview.PreviewTheme
import eu.europa.ec.uilogic.component.preview.TextLengthPreviewProvider
import eu.europa.ec.uilogic.component.preview.ThemeModePreviews

/**
 * Data class representing the configuration for text elements.
 *
 * This class provides options for customizing the appearance and behavior of text,
 * such as style, color, alignment, maximum lines, and overflow handling.
 *
 * @property style The text style to apply. Defaults to null, which means `LocalTextStyle.current` will be used.
 * @property color The color of the text. Defaults to null, which means `MaterialTheme.colorScheme.onSurface` color will be used.
 * @property textAlign The horizontal alignment of the text. Defaults to [TextAlign.Start].
 * @property maxLines The maximum number of lines the text can occupy. Defaults to 2.
 * @property overflow How visual overflow should be handled. Defaults to [TextOverflow.Ellipsis].
 * @property isHeading Whether the text is a heading, exposing heading semantics to screen readers. Defaults to false.
 */
data class TextConfig(
    val style: TextStyle? = null,
    val color: Color? = null,
    val textAlign: TextAlign = TextAlign.Start,
    val maxLines: Int = 2,
    val overflow: TextOverflow = TextOverflow.Ellipsis,
    val isHeading: Boolean = false,
)

private fun Modifier.headingSemantics(isHeading: Boolean): Modifier =
    if (isHeading) semantics { heading() } else this

@Composable
fun WrapText(
    modifier: Modifier = Modifier,
    text: String,
    textConfig: TextConfig,
) {
    Text(
        modifier = modifier.headingSemantics(textConfig.isHeading),
        text = text,
        style = textConfig.style ?: LocalTextStyle.current,
        color = textConfig.color ?: MaterialTheme.colorScheme.onSurface,
        textAlign = textConfig.textAlign,
        maxLines = textConfig.maxLines,
        overflow = textConfig.overflow,
    )
}

@Composable
fun WrapText(
    modifier: Modifier = Modifier,
    text: AnnotatedString,
    textConfig: TextConfig,
) {
    Text(
        modifier = modifier.headingSemantics(textConfig.isHeading),
        text = text,
        style = textConfig.style ?: LocalTextStyle.current,
        color = textConfig.color ?: MaterialTheme.colorScheme.onSurface,
        textAlign = textConfig.textAlign,
        maxLines = textConfig.maxLines,
        overflow = textConfig.overflow,
    )
}

@ThemeModePreviews
@Composable
private fun WrapTextConfigPreview(
    @PreviewParameter(TextLengthPreviewProvider::class) text: String
) {
    PreviewTheme {
        WrapText(
            text = text,
            textConfig = TextConfig(
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 1,
            )
        )
    }
}