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

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import eu.europa.ec.testlogic.base.TestApplication
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(application = TestApplication::class, sdk = [36])
class TestWrapStepBar {

    @get:Rule
    val composeTestRule = createComposeRule()

    @Test
    fun `Given a step bar, When a screen reader traverses it, Then no label is read out`() {
        composeTestRule.setContent {
            WrapStepBar(currentStep = 2, steps = STEPS)
        }

        // The row was read as four labels, always starting at the first.
        STEPS.forEach { step ->
            composeTestRule.onAllNodesWithText(step).assertCountEquals(0)
        }
    }

    private companion object {
        val STEPS = listOf("Welcome", "Consent", "Security", "Verification")
    }
}
