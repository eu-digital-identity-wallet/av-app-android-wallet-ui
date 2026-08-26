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

package eu.europa.ec.uilogic.component.content

import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.junit4.v2.createComposeRule
import eu.europa.ec.testlogic.base.TestApplication
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(application = TestApplication::class, sdk = [36])
class TestContentError {

    @get:Rule
    val composeTestRule = createComposeRule()

    @Test
    fun `Given an error, When a screen reader traverses it, Then the message comes before the toolbar`() {
        composeTestRule.setContent {
            ContentError(
                config = ContentErrorConfig(
                    errorTitle = "Oops!",
                    errorSubTitle = "Something went wrong",
                    onCancel = {},
                )
            )
        }

        // The toolbar sits before the content in the tree, so without this the close button is the
        // first thing reached.
        composeTestRule
            .onNode(SemanticsMatcher.expectValue(SemanticsProperties.TraversalIndex, -1f))
            .assert(SemanticsMatcher.expectValue(SemanticsProperties.IsTraversalGroup, true))
    }
}
