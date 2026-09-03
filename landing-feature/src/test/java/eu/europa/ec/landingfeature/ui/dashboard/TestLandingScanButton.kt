/*
 * Copyright (c) 2026 European Commission
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

package eu.europa.ec.landingfeature.ui.dashboard

import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import eu.europa.ec.testlogic.base.TestApplication
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(application = TestApplication::class, sdk = [36])
class TestLandingScanButton {

    @get:Rule
    val composeTestRule = createComposeRule()

    @Test
    fun `Given the dashboard scan button, When a screen reader reaches it, Then it announces Scan QR as a single actionable element`() {
        composeTestRule.setContent {
            ScanButton(onEventSend = {})
        }

        composeTestRule
            .onNodeWithContentDescription("Scan QR")
            .assertExists()

        composeTestRule
            .onNodeWithContentDescription("QR Scanner")
            .assertDoesNotExist()

        composeTestRule
            .onNodeWithText("Scan")
            .assertDoesNotExist()
    }
}
