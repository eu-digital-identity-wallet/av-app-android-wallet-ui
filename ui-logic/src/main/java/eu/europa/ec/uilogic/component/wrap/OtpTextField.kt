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
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.wrapContentSize
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.editableText
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.uilogic.component.preview.PreviewTheme
import eu.europa.ec.uilogic.component.preview.ThemeModePreviews
import eu.europa.ec.uilogic.component.utils.OneTimeLaunchedEffect
import eu.europa.ec.uilogic.component.utils.SIZE_EXTRA_SMALL
import eu.europa.ec.uilogic.component.utils.SIZE_SMALL

/**
 * PIN entry field: a single [BasicTextField] whose [BasicTextField.decorationBox] draws one box per
 * digit.
 *
 * Screen readers see the digit row, not the text field: it announces the prefix plus how many
 * digits are in, and any error, but never the digits themselves.
 *
 * @param accessibilityPrefixResId Pass a distinct prefix where the same field is reused for a
 * second PIN, so the two steps do not sound identical.
 * @param lockoutMessage Rendered like [errorMessage] but never announced, since it changes on a
 * timer.
 */
@Composable
fun OtpTextField(
    modifier: Modifier = Modifier,
    otpText: String,
    length: Int = 6,
    onUpdate: (String) -> Unit,
    visualTransformation: VisualTransformation = VisualTransformation.None,
    pinWidth: Dp = 40.dp,
    hasError: Boolean = false,
    errorMessage: String? = null,
    lockoutMessage: String? = null,
    focusOnCreate: Boolean = false,
    enabled: Boolean = true,
    accessibilityPrefix: String,
) {
    LaunchedEffect(Unit) {
        if (otpText.length > length) {
            throw IllegalArgumentException("Otp text value must not have more than otpCount: $length characters")
        }
    }

    val focusRequester = remember { FocusRequester() }

    val emptyLabel = stringResource(id = R.string.content_description_pin_input_empty)
    val digitsEnteredLabel = stringResource(
        id = R.string.content_description_pin_digits_entered,
        otpText.length,
        length
    )
    // Progress and errors arrive on the same keystroke, so one region carries both - two race.
    val pinDescription = buildString {
        append(accessibilityPrefix)
        append(": ")
        append(if (otpText.isEmpty()) emptyLabel else digitsEnteredLabel)
        if (!errorMessage.isNullOrEmpty()) {
            append(". ")
            append(errorMessage)
        }
    }

    Column(modifier = modifier) {
        BasicTextField(
            modifier = Modifier
                .focusRequester(focusRequester)
                // The mask lands in EditableText, where it is read out as "bullet" per digit.
                .semantics { editableText = AnnotatedString("") },
            value = TextFieldValue(otpText, selection = TextRange(otpText.length)),
            onValueChange = {
                if (!enabled) return@BasicTextField
                if (it.text.length > length) {
                    return@BasicTextField
                }
                onUpdate.invoke(it.text)
            },
            enabled = enabled,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
            visualTransformation = visualTransformation,
            decorationBox = {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .semantics {
                            contentDescription = pinDescription
                            liveRegion = if (errorMessage.isNullOrEmpty()) {
                                LiveRegionMode.Polite
                            } else {
                                LiveRegionMode.Assertive
                            }
                        },
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    repeat(length) { index ->
                        CharView(
                            index = index,
                            text = visualTransformation.filter(AnnotatedString(otpText)).text.text,
                            pinWidth = pinWidth,
                            hasError = hasError,
                            enabled = enabled,
                        )

                    }
                }
            })

        // The countdown replaces the static lockout text rather than stacking under it. Only
        // errorMessage reaches the description above, so the lockout is announced once and the
        // countdown never is.
        (lockoutMessage?.takeIf { it.isNotEmpty() } ?: errorMessage?.takeIf { it.isNotEmpty() })?.let {
            WrapText(
                text = it,
                textConfig = TextConfig(
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    maxLines = Int.MAX_VALUE,
                ),
                modifier = Modifier.padding(top = 4.dp)
            )
        }

        OneTimeLaunchedEffect {
            if (focusOnCreate && enabled) {
                focusRequester.requestFocus()
            }
        }
    }

}

@Composable
fun PinHintText(pinHintText: String) {
    WrapText(
        textConfig = TextConfig(style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.inverseSurface.copy(alpha = 0.66f)),
        text = pinHintText
    )
}

@Composable
private fun CharView(
    index: Int,
    text: String,
    pinWidth: Dp = 40.dp,
    hasError: Boolean = false,
    enabled: Boolean = true,
) {
    val isFocused = text.length == index
    val char = when {
        index >= text.length -> ""
        else -> text[index].toString()
    }

    val borderColor = when {
        hasError -> MaterialTheme.colorScheme.error
        isFocused && enabled -> MaterialTheme.colorScheme.primary
        !enabled -> MaterialTheme.colorScheme.inverseSurface.copy(alpha = 0.3f)
        else -> MaterialTheme.colorScheme.inverseSurface.copy(alpha = 0.5f)
    }

    val backgroundColor = if (enabled) {
        MaterialTheme.colorScheme.onPrimary
    } else {
        MaterialTheme.colorScheme.inverseSurface.copy(alpha = 0.1f)
    }

    val textColor = if (enabled) {
        MaterialTheme.colorScheme.onSurface
    } else {
        MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f)
    }

    val borderWidth = when {
        isFocused && enabled -> 2.dp
        else -> 1.dp
    }
    Text(
        style = MaterialTheme.typography.headlineMedium.copy(color = textColor),
        textAlign = TextAlign.Center,
        text = char,
        modifier = Modifier
            .width(pinWidth)
            .clearAndSetSemantics { }
            .border(
                width = borderWidth,
                color = borderColor,
                shape = RoundedCornerShape(SIZE_EXTRA_SMALL.dp)
            )
            .background(backgroundColor)
            .padding(vertical = SIZE_SMALL.dp)
    )

}


@ThemeModePreviews
@Composable
private fun PreviewOtpTextField() {
    PreviewTheme {
        Column {
            OtpTextField(
                modifier = Modifier.wrapContentSize(),
                onUpdate = {},
                length = 6,
                otpText = "123456",
                visualTransformation = PasswordVisualTransformation(),
                pinWidth = 42.dp,
                accessibilityPrefix = "PIN",
            )
        }

    }
}


@ThemeModePreviews
@Composable
private fun PreviewOtpTextFieldWithError() {
    PreviewTheme {
        OtpTextField(
            modifier = Modifier.wrapContentSize(),
            onUpdate = {},
            length = 6,
            otpText = "123",
            visualTransformation = PasswordVisualTransformation(),
            pinWidth = 42.dp,
            hasError = true,
            errorMessage = "Invalid code",
            accessibilityPrefix = "PIN",
        )
    }
}
