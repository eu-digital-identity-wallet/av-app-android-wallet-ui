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

package eu.europa.ec.uilogic.component

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.size
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import eu.europa.ec.uilogic.component.preview.PreviewTheme
import eu.europa.ec.uilogic.component.preview.ThemeModePreviews
import eu.europa.ec.uilogic.component.utils.SIZE_SMALL
import eu.europa.ec.uilogic.component.utils.screenHeightInDp
import eu.europa.ec.uilogic.component.utils.screenWidthInDp
import eu.europa.ec.uilogic.component.wrap.WrapIcon

@Composable
fun ErrorInfo(
    informativeText: String,
    modifier: Modifier = Modifier,
    contentColor: Color = MaterialTheme.colorScheme.onSurface,
    isIconEnabled: Boolean = false,
) {

    val errorIconSize = minOf(screenWidthInDp(true), screenHeightInDp(true)) / 6

    Column(
        modifier = modifier,
        verticalArrangement = Arrangement.spacedBy(SIZE_SMALL.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        WrapIcon(
            iconData = AppIcons.Error,
            modifier = Modifier.size(errorIconSize),
            customTint = contentColor,
            enabled = isIconEnabled,
        )
        Text(
            text = informativeText,
            style = MaterialTheme.typography.bodyMedium,
            color = contentColor,
            textAlign = TextAlign.Center,
            lineHeight = 20.sp
        )
    }
}

@ThemeModePreviews
@Composable
private fun ErrorInfoPreview() {
    PreviewTheme {
        ErrorInfo(
            informativeText = "No data available",
            modifier = Modifier
        )
    }
}