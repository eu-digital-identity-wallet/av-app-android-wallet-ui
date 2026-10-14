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

package eu.europa.ec.commonfeature.ui.request.transformer

import eu.europa.ec.businesslogic.provider.UuidProvider
import eu.europa.ec.commonfeature.extension.toSelectiveExpandableListItems
import eu.europa.ec.commonfeature.ui.request.model.DocumentPayloadDomain
import eu.europa.ec.commonfeature.ui.request.model.DomainDocumentFormat
import eu.europa.ec.commonfeature.ui.request.model.RequestDocumentItemUi
import eu.europa.ec.commonfeature.util.docNamespace
import eu.europa.ec.commonfeature.util.transformPathsToDomainClaims
import eu.europa.ec.corelogic.extension.toClaimPath
import eu.europa.ec.corelogic.extension.toClaimPaths
import eu.europa.ec.corelogic.model.ClaimPathDomain
import eu.europa.ec.corelogic.model.ClaimPathDomain.Companion.isPrefixOf
import eu.europa.ec.eudi.iso18013.transfer.response.DisclosedDocument
import eu.europa.ec.eudi.iso18013.transfer.response.DisclosedDocuments
import eu.europa.ec.eudi.iso18013.transfer.response.RequestedDocument
import eu.europa.ec.eudi.iso18013.transfer.response.device.MsoMdocItem
import eu.europa.ec.eudi.wallet.document.IssuedDocument
import eu.europa.ec.eudi.wallet.transfer.openId4vp.SdJwtVcItem
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.uilogic.component.ListItemDataUi
import eu.europa.ec.uilogic.component.ListItemMainContentDataUi
import eu.europa.ec.uilogic.component.ListItemTrailingContentDataUi
import eu.europa.ec.uilogic.component.wrap.ExpandableListItemUi

object RequestTransformer {

    fun transformToDomainItems(
        storageDocuments: List<IssuedDocument>,
        resourceProvider: ResourceProvider,
        uuidProvider: UuidProvider,
        requestDocuments: List<RequestedDocument>,
    ): Result<List<DocumentPayloadDomain>> = runCatching {
        val resultList = mutableListOf<DocumentPayloadDomain>()

        requestDocuments.forEach { requestDocument ->

            val storageDocument =
                storageDocuments.first { it.id == requestDocument.documentId }

            val claimsPaths = storageDocument.data.claims.flatMap { claim ->
                claim.toClaimPaths()
            }

            val requestedItemsPaths = requestDocument.requestedItems.keys
                .map {
                    it.toClaimPath()
                }

            val filteredPaths = claimsPaths.filter { available ->
                requestedItemsPaths.any { requested ->
                    requested.isPrefixOf(available)
                }
            }

            val domainClaims = transformPathsToDomainClaims(
                paths = filteredPaths,
                claims = storageDocument.data.claims,
                resourceProvider = resourceProvider,
                uuidProvider = uuidProvider
            )

            if (domainClaims.isNotEmpty()) {
                resultList.add(
                    DocumentPayloadDomain(
                        docName = storageDocument.name,
                        docId = storageDocument.id,
                        domainDocFormat = DomainDocumentFormat.getFormat(
                            format = storageDocument.format,
                            namespace = storageDocument.docNamespace
                        ),
                        docClaimsDomain = domainClaims
                    )
                )
            }
        }

        resultList
    }


    fun transformToUiItems(
        documentsDomain: List<DocumentPayloadDomain>,
    ): List<RequestDocumentItemUi> {
        return documentsDomain.map {
            RequestDocumentItemUi(
                domainPayload = it,
                headerUi = ExpandableListItemUi.NestedListItem(
                    header = ListItemDataUi(
                        itemId = it.docId,
                        mainContentData = ListItemMainContentDataUi.Text(text = it.docName),
                    ),
                    nestedItems = it.toSelectiveExpandableListItems(),
                    isExpanded = false,
                ),
            )
        }
    }

    fun createDisclosedDocuments(items: List<RequestDocumentItemUi>): DisclosedDocuments {
        // Collect all selected expanded items from the list
        fun ExpandableListItemUi.collectSingles(): List<ExpandableListItemUi.SingleListItem> =
            when (this) {
                is ExpandableListItemUi.SingleListItem -> {
                    val isSelected =
                        header.trailingContentData is ListItemTrailingContentDataUi.Checkbox &&
                                (header.trailingContentData as ListItemTrailingContentDataUi.Checkbox)
                                    .checkboxData.isChecked
                    if (isSelected) listOf(this) else emptyList()
                }

                is ExpandableListItemUi.NestedListItem -> nestedItems.flatMap { it.collectSingles() }
            }

        val groupedByDocument = items.map { document ->
            document.domainPayload to document.headerUi.nestedItems.flatMap { uiItem ->
                uiItem.collectSingles()
                    .distinctBy { listItemDataUi ->
                        listItemDataUi.header.itemId // Distinct by item ID to prevent duplicate sending of the same group
                    }
            }
        }

        // Convert to the format required by DisclosedDocuments
        val disclosedDocuments: List<DisclosedDocument> =
            groupedByDocument.mapNotNull { (documentPayload, selectedItemsForDocument) ->

                val mDocItems: MutableList<MsoMdocItem> = mutableListOf()
                val sdJwtItems: MutableList<SdJwtVcItem> = mutableListOf()

                selectedItemsForDocument.forEach { selectedItem ->

                    val selectedItemId = selectedItem.header.itemId

                    when (documentPayload.domainDocFormat) {

                        is DomainDocumentFormat.SdJwtVc -> sdJwtItems.add(
                            SdJwtVcItem(
                                path = ClaimPathDomain.toSdJwtVcPath(selectedItemId)
                            )
                        )

                        is DomainDocumentFormat.MsoMdoc -> mDocItems.add(
                            MsoMdocItem(
                                namespace = documentPayload.domainDocFormat.namespace,
                                elementIdentifier = ClaimPathDomain.toElementIdentifier(
                                    selectedItemId
                                )
                            )
                        )
                    }
                }

                val disclosedItems = mDocItems.distinctBy { it.elementIdentifier } + sdJwtItems

                return@mapNotNull if (disclosedItems.isNotEmpty()) {
                    DisclosedDocument(
                        documentId = documentPayload.docId,
                        disclosedItems = disclosedItems,
                        keyUnlockData = null
                    )
                } else {
                    null
                }
            }

        return DisclosedDocuments(disclosedDocuments)
    }
}
