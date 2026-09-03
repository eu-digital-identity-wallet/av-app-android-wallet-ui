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

package eu.europa.ec.uilogic.component.wrap

import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.text.input.PasswordVisualTransformation
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.testlogic.base.TestApplication
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@RunWith(RobolectricTestRunner::class)
@Config(application = TestApplication::class, sdk = [36])
class TestOtpTextField {

    @get:Rule
    val composeTestRule = createComposeRule()

    @Test
    fun `Given an empty PIN, When the field is shown, Then it is announced as empty`() {
        composeTestRule.setContent {
            OtpTextField(otpText = "", onUpdate = {}, accessibilityPrefix = "PIN")
        }

        composeTestRule.onNodeWithContentDescription("PIN: empty").assertIsDisplayed()
    }

    @Test
    fun `Given three digits entered, When the field is shown, Then the progress is announced`() {
        composeTestRule.setContent {
            OtpTextField(
                otpText = "123",
                onUpdate = {},
                accessibilityPrefix = "PIN",
                visualTransformation = PasswordVisualTransformation(),
            )
        }

        composeTestRule.onNodeWithContentDescription("PIN: 3 of 6 digits entered")
            .assertIsDisplayed()
    }

    @Test
    fun `Given a full PIN, When the field is announced, Then the digits are never spoken`() {
        composeTestRule.setContent {
            OtpTextField(
                otpText = "123456",
                onUpdate = {},
                accessibilityPrefix = "PIN",
                visualTransformation = PasswordVisualTransformation(),
            )
        }

        val config = composeTestRule.onNodeWithContentDescription("PIN: 6 of 6 digits entered")
            .fetchSemanticsNode()
            .config

        // The raw value survives only in InputText, which is for autofill and is not spoken.
        assertTrue(config.contains(SemanticsProperties.Password))
        assertFalse(config[SemanticsProperties.ContentDescription].any { it.contains("123456") })
        assertFalse(config[SemanticsProperties.EditableText].text.contains("123456"))
    }

    @Test
    fun `Given a masked PIN, When the field is announced, Then the mask is not read out`() {
        composeTestRule.setContent {
            OtpTextField(
                otpText = "123456",
                onUpdate = {},
                accessibilityPrefix = "PIN",
                visualTransformation = PasswordVisualTransformation(),
            )
        }

        // EditableText is read as the field value, and U+2022 is spoken as "bullet".
        val editableText = composeTestRule
            .onNodeWithContentDescription("PIN: 6 of 6 digits entered")
            .fetchSemanticsNode()
            .config[SemanticsProperties.EditableText]
            .text

        assertEquals("", editableText)
    }

    @Test
    fun `Given the field is shown, When a digit lands, Then the row is a polite live region`() {
        composeTestRule.setContent {
            OtpTextField(otpText = "1", onUpdate = {}, accessibilityPrefix = "PIN")
        }

        composeTestRule.onNodeWithContentDescription("PIN: 1 of 6 digits entered")
            .assert(
                SemanticsMatcher.expectValue(
                    SemanticsProperties.LiveRegion,
                    LiveRegionMode.Polite
                )
            )
    }

    @Test
    fun `Given a repeated PIN prefix, When the field is shown, Then that prefix is announced`() {
        composeTestRule.setContent {
            OtpTextField(
                otpText = "",
                onUpdate = {},
                accessibilityPrefix = "repeated PIN",
            )
        }

        composeTestRule.onNodeWithContentDescription("repeated PIN: empty").assertIsDisplayed()
    }

    @Test
    fun `Given an error, When it is shown, Then the field announces it assertively`() {
        composeTestRule.setContent {
            OtpTextField(
                otpText = "123456",
                onUpdate = {},
                accessibilityPrefix = "PIN",
                hasError = true,
                errorMessage = "PINs do not match",
            )
        }

        // One region carries both, since two would race on the same keystroke.
        composeTestRule.onNodeWithContentDescription(
            "PIN: 6 of 6 digits entered. PINs do not match"
        ).assert(
            SemanticsMatcher.expectValue(
                SemanticsProperties.LiveRegion,
                LiveRegionMode.Assertive
            )
        )
    }

    @Test
    fun `Given an error, When it is shown, Then it is not a second live region`() {
        composeTestRule.setContent {
            OtpTextField(
                otpText = "123456",
                onUpdate = {},
                accessibilityPrefix = "PIN",
                hasError = true,
                errorMessage = "PINs do not match",
            )
        }

        composeTestRule.onNodeWithText("PINs do not match")
            .assert(SemanticsMatcher.keyIsDefined(SemanticsProperties.LiveRegion).not())
    }

    @Test
    fun `Given a lockout countdown, When it is shown, Then it is not announced`() {
        composeTestRule.setContent {
            OtpTextField(
                otpText = "",
                onUpdate = {},
                accessibilityPrefix = "PIN",
                lockoutMessage = "Account locked. Try again in 42 seconds",
            )
        }

        composeTestRule.onNodeWithText("Account locked. Try again in 42 seconds")
            .assert(SemanticsMatcher.keyIsDefined(SemanticsProperties.LiveRegion).not())
    }
}
