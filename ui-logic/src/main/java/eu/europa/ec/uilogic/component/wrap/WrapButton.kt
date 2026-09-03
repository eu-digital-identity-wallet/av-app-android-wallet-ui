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

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.focusable
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonColors
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.unit.dp
import eu.europa.ec.uilogic.component.preview.PreviewTheme
import eu.europa.ec.uilogic.component.preview.ThemeModePreviews
import eu.europa.ec.uilogic.component.utils.ALPHA_DISABLED
import eu.europa.ec.uilogic.component.utils.SIZE_SMALL
import eu.europa.ec.uilogic.component.utils.SPACING_LARGE

enum class ButtonType {
    PRIMARY,
    SECONDARY,
}

internal val buttonsShape: RoundedCornerShape = RoundedCornerShape(SIZE_SMALL.dp)

internal val buttonsContentPadding: PaddingValues = PaddingValues(
    vertical = 10.dp,
    horizontal = SPACING_LARGE.dp
)

data class ButtonConfig(
    val type: ButtonType,
    val enabled: Boolean = true,
    val onClick: () -> Unit,
    val isWarning: Boolean = false,
    val shape: Shape = buttonsShape,
    val contentPadding: PaddingValues = buttonsContentPadding,
    val buttonColors: ButtonColors? = null,
    val focusRequester: FocusRequester? = null,
)

@Composable
fun WrapButton(
    modifier: Modifier = Modifier,
    buttonConfig: ButtonConfig,
    content: @Composable RowScope.() -> Unit,
) {
    // Buttons are only focusable outside touch mode, so screen-reader focus needs its own target.
    val focusModifier = buttonConfig.focusRequester?.let { requester ->
        Modifier.focusRequester(requester).focusable(enabled = buttonConfig.enabled)
    } ?: Modifier

    when (buttonConfig.type) {
        ButtonType.PRIMARY -> WrapPrimaryButton(
            modifier = modifier.then(focusModifier),
            buttonConfig = buttonConfig,
            content = content,
        )

        ButtonType.SECONDARY -> WrapSecondaryButton(
            modifier = modifier.then(focusModifier),
            buttonConfig = buttonConfig,
            content = content,
        )
    }
}

@Composable
private fun WrapPrimaryButton(
    modifier: Modifier = Modifier,
    buttonConfig: ButtonConfig,
    content: @Composable RowScope.() -> Unit,
) {
    val (containerColor, contentColor) = if (buttonConfig.isWarning) {
        MaterialTheme.colorScheme.error to MaterialTheme.colorScheme.onError
    } else {
        MaterialTheme.colorScheme.primary to MaterialTheme.colorScheme.onPrimary
    }

    val disabledContentColor = contentColor.copy(
        alpha = ALPHA_DISABLED
    )
    val disabledContainerColor = containerColor.copy(
        alpha = ALPHA_DISABLED
    )

    val colors = buttonConfig.buttonColors ?: ButtonDefaults.buttonColors(
        containerColor = containerColor,
        disabledContainerColor = disabledContainerColor,
        contentColor = contentColor,
        disabledContentColor = disabledContentColor,
    )

    Button(
        modifier = modifier,
        enabled = buttonConfig.enabled,
        onClick = buttonConfig.onClick,
        shape = buttonConfig.shape,
        colors = colors,
        contentPadding = buttonConfig.contentPadding,
        content = content
    )
}

@Composable
private fun WrapSecondaryButton(
    modifier: Modifier = Modifier,
    buttonConfig: ButtonConfig,
    content: @Composable RowScope.() -> Unit,
) {
    val (contentColor, borderColor) = if (buttonConfig.isWarning) {
        MaterialTheme.colorScheme.error to MaterialTheme.colorScheme.error
    } else {
        MaterialTheme.colorScheme.primary to MaterialTheme.colorScheme.primary
    }

    val disabledContentColor = contentColor.copy(
        alpha = ALPHA_DISABLED
    )
    val disabledBorderColor = borderColor.copy(
        alpha = ALPHA_DISABLED
    )

    val colors = buttonConfig.buttonColors ?: ButtonDefaults.outlinedButtonColors(
        contentColor = contentColor,
        disabledContentColor = disabledContentColor,
    )

    OutlinedButton(
        modifier = modifier,
        enabled = buttonConfig.enabled,
        onClick = buttonConfig.onClick,
        shape = buttonConfig.shape,
        colors = colors,
        border = BorderStroke(
            width = 1.dp,
            color = if (buttonConfig.enabled) {
                borderColor
            } else {
                disabledBorderColor
            },
        ),
        contentPadding = buttonConfig.contentPadding,
        content = content
    )
}

@ThemeModePreviews
@Composable
private fun WrapPrimaryButtonEnabledPreview() {
    PreviewTheme {
        WrapButton(
            buttonConfig = ButtonConfig(
                type = ButtonType.PRIMARY,
                enabled = true,
                onClick = { }
            ),
        ) {
            Text("Enabled Primary Button")
        }
    }
}

@ThemeModePreviews
@Composable
private fun WrapPrimaryButtonDisabledPreview() {
    PreviewTheme {
        WrapButton(
            buttonConfig = ButtonConfig(
                type = ButtonType.PRIMARY,
                enabled = false,
                onClick = { }
            ),
        ) {
            Text("Disabled Primary Button")
        }
    }
}

@ThemeModePreviews
@Composable
private fun WrapPrimaryButtonEnabledWarningPreview() {
    PreviewTheme {
        WrapButton(
            buttonConfig = ButtonConfig(
                type = ButtonType.PRIMARY,
                enabled = true,
                isWarning = true,
                onClick = { }
            )
        ) {
            Text("Enabled Warning Primary Button")
        }
    }
}

@ThemeModePreviews
@Composable
private fun WrapPrimaryButtonDisabledWarningPreview() {
    PreviewTheme {
        WrapButton(
            buttonConfig = ButtonConfig(
                type = ButtonType.PRIMARY,
                enabled = false,
                isWarning = true,
                onClick = { }
            )
        ) {
            Text("Disabled Warning Primary Button")
        }
    }
}

@ThemeModePreviews
@Composable
private fun WrapSecondaryButtonEnabledPreview() {
    PreviewTheme {
        WrapButton(
            buttonConfig = ButtonConfig(
                type = ButtonType.SECONDARY,
                enabled = true,
                onClick = { }
            )
        ) {
            Text("Enabled Secondary Button")
        }
    }
}

@ThemeModePreviews
@Composable
private fun WrapSecondaryButtonDisabledPreview() {
    PreviewTheme {
        WrapButton(
            buttonConfig = ButtonConfig(
                type = ButtonType.SECONDARY,
                enabled = false,
                onClick = { }
            )
        ) {
            Text("Disabled Secondary Button")
        }
    }
}

@ThemeModePreviews
@Composable
private fun WrapSecondaryButtonEnabledWarningPreview() {
    PreviewTheme {
        WrapButton(
            buttonConfig = ButtonConfig(
                type = ButtonType.SECONDARY,
                enabled = true,
                isWarning = true,
                onClick = { }
            )
        ) {
            Text("Enabled Warning Secondary Button")
        }
    }
}

@ThemeModePreviews
@Composable
private fun WrapSecondaryButtonDisabledWarningPreview() {
    PreviewTheme {
        WrapButton(
            buttonConfig = ButtonConfig(
                type = ButtonType.SECONDARY,
                enabled = false,
                isWarning = true,
                onClick = { }
            )
        ) {
            Text("Disabled Warning Secondary Button")
        }
    }
}