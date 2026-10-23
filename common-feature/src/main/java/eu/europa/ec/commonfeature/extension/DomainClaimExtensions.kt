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

package eu.europa.ec.commonfeature.extension

import eu.europa.ec.commonfeature.ui.request.model.DocumentPayloadDomain
import eu.europa.ec.commonfeature.util.keyIsPortrait
import eu.europa.ec.commonfeature.util.keyIsSignature
import eu.europa.ec.corelogic.model.ClaimDomain
import eu.europa.ec.eudi.wallet.document.ElementIdentifier
import eu.europa.ec.uilogic.component.ListItemDataUi
import eu.europa.ec.uilogic.component.ListItemLeadingContentDataUi
import eu.europa.ec.uilogic.component.ListItemMainContentDataUi
import eu.europa.ec.uilogic.component.ListItemTrailingContentDataUi
import eu.europa.ec.uilogic.component.wrap.CheckboxDataUi
import eu.europa.ec.uilogic.component.wrap.ExpandableListItemUi

fun DocumentPayloadDomain.toSelectiveExpandableListItems(): List<ExpandableListItemUi> {
    return this.docClaimsDomain.map { claim ->
        claim.toSelectiveExpandableListItems(docId)
    }
}

fun ClaimDomain.toSelectiveExpandableListItems(docId: String): ExpandableListItemUi {
    return when (this) {
        is ClaimDomain.Group -> {
            ExpandableListItemUi.NestedListItem(
                header = ListItemDataUi(
                    itemId = path.toId(docId),
                    mainContentData = ListItemMainContentDataUi.Text(text = displayTitle),
                ),
                nestedItems = items.map {
                    it.toSelectiveExpandableListItems(docId)
                },
                isExpanded = true
            )
        }

        is ClaimDomain.Primitive -> {
            ExpandableListItemUi.SingleListItem(
                header = ListItemDataUi(
                    itemId = path.toId(docId),
                    mainContentData = calculateMainContent(key, value),
                    overlineText = calculateOverlineText(displayTitle),
                    leadingContentData = calculateLeadingContent(key, value),
                    trailingContentData = ListItemTrailingContentDataUi.Checkbox(
                        checkboxData = CheckboxDataUi(
                            isChecked = true,
                            enabled = !isRequired
                        )
                    )
                )
            )
        }
    }
}

fun ClaimDomain.toExpandableListItems(docId: String): ExpandableListItemUi {
    return when (this) {
        is ClaimDomain.Group -> {
            ExpandableListItemUi.NestedListItem(
                header = ListItemDataUi(
                    itemId = path.toId(docId),
                    mainContentData = ListItemMainContentDataUi.Text(text = displayTitle),
                ),
                nestedItems = items.map { it.toExpandableListItems(docId = docId) },
                isExpanded = true
            )
        }

        is ClaimDomain.Primitive -> {
            ExpandableListItemUi.SingleListItem(
                header = ListItemDataUi(
                    itemId = path.toId(docId),
                    mainContentData = calculateMainContent(key, value),
                    overlineText = calculateOverlineText(displayTitle),
                    leadingContentData = calculateLeadingContent(key, value),
                )
            )
        }
    }
}

private fun calculateMainContent(
    key: ElementIdentifier,
    value: String,
): ListItemMainContentDataUi {
    return when {
        keyIsPortrait(key = key) -> {
            ListItemMainContentDataUi.Text(text = "")
        }

        keyIsSignature(key = key) -> {
            ListItemMainContentDataUi.Image(base64Image = value)
        }

        else -> {
            ListItemMainContentDataUi.Text(text = value)
        }
    }
}

private fun calculateLeadingContent(
    key: ElementIdentifier,
    value: String,
): ListItemLeadingContentDataUi? {
    return if (keyIsPortrait(key = key)) {
        ListItemLeadingContentDataUi.UserImage(userBase64Image = value)
    } else {
        null
    }
}

private fun calculateOverlineText(displayTitle: String): String? {
    return displayTitle.ifBlank {
        null
    }
}