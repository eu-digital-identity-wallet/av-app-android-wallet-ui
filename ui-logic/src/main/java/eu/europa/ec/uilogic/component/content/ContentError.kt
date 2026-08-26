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

package eu.europa.ec.uilogic.component.content

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.semantics.isTraversalGroup
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.traversalIndex
import androidx.compose.ui.unit.dp
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.uilogic.component.IconDataUi
import eu.europa.ec.uilogic.component.preview.PreviewTheme
import eu.europa.ec.uilogic.component.preview.ThemeModePreviews
import eu.europa.ec.uilogic.component.utils.SIZE_MEDIUM
import eu.europa.ec.uilogic.component.utils.SIZE_100
import eu.europa.ec.uilogic.component.wrap.ButtonConfig
import eu.europa.ec.uilogic.component.wrap.ButtonType
import eu.europa.ec.uilogic.component.wrap.WrapButton
import eu.europa.ec.uilogic.component.wrap.WrapImage

private const val TOP_APP_BAR_HEIGHT = 64

@Composable
internal fun ContentError(
    config: ContentErrorConfig,
    modifier: Modifier = Modifier,
) {
    val errorTitle = config.errorTitle ?: stringResource(id = R.string.generic_error_message)
    val errorSubTitle = config.errorSubTitle ?: stringResource(id = R.string.generic_error_retry)

    // A live region does not fire for a node that appears with the error already in it, so the
    // message is announced explicitly. Without this the first thing heard is the toolbar's close
    // button, and the caption is only reachable by swiping back to it.
    val view = LocalView.current
    val announcement = stringResource(
        id = R.string.content_description_sentence_pair,
        errorTitle,
        errorSubTitle
    )
    LaunchedEffect(announcement) {
        @Suppress("DEPRECATION")
        view.announceForAccessibility(announcement)
    }

    ScrollableFullHeightColumn(
        // Sorts the error ahead of the toolbar, so swiping starts on the message not the close
        // button.
        modifier = modifier.semantics {
            isTraversalGroup = true
            traversalIndex = -1f
        },
        verticalArrangement = Arrangement.SpaceBetween,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.semantics(mergeDescendants = true) {},
        ) {
            config.icon?.let { iconData ->
                Spacer(modifier = Modifier.height(TOP_APP_BAR_HEIGHT.dp))
                WrapImage(
                    iconData = iconData,
                    modifier = Modifier.size(SIZE_100.dp),
                )
                Spacer(modifier = Modifier.height(SIZE_MEDIUM.dp))
            }

            ContentTitle(
                title = errorTitle,
                subtitle = errorSubTitle,
                subTitleMaxLines = 10
            )
        }

        config.onRetry?.let { callback ->
            WrapButton(
                buttonConfig = ButtonConfig(
                    type = ButtonType.PRIMARY,
                    onClick = {
                        callback()
                    },
                ),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = stringResource(id = R.string.generic_error_button_retry)
                )
            }
        }
    }
}

data class ContentErrorConfig(
    val errorTitle: String? = null,
    val errorSubTitle: String? = null,
    val icon: IconDataUi? = null,
    val onCancel: () -> Unit,
    val onRetry: (() -> Unit)? = null
)

@ThemeModePreviews
@Composable
private fun PreviewContentErrorWithRetry() {
    PreviewTheme {
        ContentError(
            config = ContentErrorConfig(
                onCancel = {},
                onRetry = {},
            ),
            modifier = Modifier.padding(SIZE_MEDIUM.dp)
        )
    }
}

@ThemeModePreviews
@Composable
private fun PreviewContentErrorWithoutRetry() {
    PreviewTheme {
        ContentError(
            config = ContentErrorConfig(
                onCancel = {},
                onRetry = null,
            ),
            modifier = Modifier.padding(SIZE_MEDIUM.dp)
        )
    }
}