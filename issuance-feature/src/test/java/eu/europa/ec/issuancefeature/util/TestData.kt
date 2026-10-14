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

package eu.europa.ec.issuancefeature.util

import eu.europa.ec.corelogic.model.ScopedDocumentDomain
import eu.europa.ec.eudi.openid4vci.TxCode
import eu.europa.ec.eudi.openid4vci.TxCodeInputMode
import eu.europa.ec.issuancefeature.ui.add.model.AddDocumentUi
import eu.europa.ec.testfeature.util.mockedAgeVerificationDocName
import eu.europa.ec.testfeature.util.mockedMdlDocName
import eu.europa.ec.testfeature.util.mockedMdocAgeVerificationFormat
import eu.europa.ec.testfeature.util.mockedMdocMdlFormat
import eu.europa.ec.testfeature.util.mockedMdocPhotoIdFormat
import eu.europa.ec.testfeature.util.mockedMdocPidFormat
import eu.europa.ec.testfeature.util.mockedPhotoIdDocName
import eu.europa.ec.testfeature.util.mockedPidDocName
import eu.europa.ec.testfeature.util.mockedPidId
import eu.europa.ec.testfeature.util.mockedSdJwtPidId
import eu.europa.ec.testfeature.util.mockedUuid
import eu.europa.ec.uilogic.component.AppIcons
import eu.europa.ec.uilogic.component.ListItemDataUi
import eu.europa.ec.uilogic.component.ListItemMainContentDataUi
import eu.europa.ec.uilogic.component.ListItemTrailingContentDataUi
import eu.europa.ec.uilogic.component.wrap.ExpandableListItemUi
import eu.europa.ec.uilogic.config.ConfigNavigation
import eu.europa.ec.uilogic.config.NavigationType
import eu.europa.ec.uilogic.navigation.IssuanceScreens
import eu.europa.ec.uilogic.navigation.LandingScreens

internal const val mockedOfferedDocumentName = "Offered Document"
internal const val mockedOfferedDocumentDocType = "mocked_offered_document_doc_type"
internal const val mockedTxCodeFourDigits = 4
internal const val mockedSuccessContentDescription = "Content description"
internal const val mockedIssuanceErrorMessage = "Issuance error message"
internal const val mockedInvalidCodeFormatMessage = "Invalid code format message"
internal const val mockedWalletActivationErrorMessage = "Wallet activation error message"
internal const val mockedPrimaryButtonText = "Primary button text"
internal const val mockedRouteArguments = "mockedRouteArguments"
internal const val mockedTxCode = "mockedTxCode"
internal const val mockedSuccessText = "Success text"
internal const val mockedSuccessDescription = "Success description"
internal const val mockedErrorDescription = "Error description"
internal const val mockedIssuerId = "issuerId"

private const val mockedConfigIssuerId = "configurationId"

internal val mockedPidOptionItemUi = AddDocumentUi(
    credentialIssuerId = mockedIssuerId,
    configurationId = mockedConfigIssuerId,
    itemData = ListItemDataUi(
        itemId = mockedConfigIssuerId,
        mainContentData = ListItemMainContentDataUi.Text(text = mockedPidDocName),
        trailingContentData = ListItemTrailingContentDataUi.Icon(iconData = AppIcons.Add)
    ),
)

internal val mockedMdlOptionItemUi = AddDocumentUi(
    credentialIssuerId = mockedIssuerId,
    configurationId = mockedConfigIssuerId,
    itemData = ListItemDataUi(
        itemId = mockedConfigIssuerId,
        mainContentData = ListItemMainContentDataUi.Text(text = mockedMdlDocName),
        trailingContentData = ListItemTrailingContentDataUi.Icon(iconData = AppIcons.Add)
    ),
)

internal val mockedAgeOptionItemUi = AddDocumentUi(
    credentialIssuerId = mockedIssuerId,
    configurationId = mockedConfigIssuerId,
    itemData = ListItemDataUi(
        itemId = mockedConfigIssuerId,
        mainContentData = ListItemMainContentDataUi.Text(text = mockedAgeVerificationDocName),
        trailingContentData = ListItemTrailingContentDataUi.Icon(iconData = AppIcons.Add)
    ),
)

internal val mockedPhotoIdOptionItemUi = AddDocumentUi(
    credentialIssuerId = mockedIssuerId,
    configurationId = mockedConfigIssuerId,
    itemData = ListItemDataUi(
        itemId = mockedConfigIssuerId,
        mainContentData = ListItemMainContentDataUi.Text(text = mockedPhotoIdDocName),
        trailingContentData = ListItemTrailingContentDataUi.Icon(iconData = AppIcons.Add)
    ),
)

internal val mockedScopedDocuments: List<ScopedDocumentDomain>
    get() = listOf(
        ScopedDocumentDomain(
            name = mockedPidDocName,
            configurationId = mockedConfigIssuerId,
            credentialIssuerId = mockedIssuerId,
            isPid = true,
            isAgeVerification = false,
            formatType = mockedMdocPidFormat.docType
        ),
        ScopedDocumentDomain(
            name = mockedMdlDocName,
            configurationId = mockedConfigIssuerId,
            credentialIssuerId = mockedIssuerId,
            isPid = false,
            isAgeVerification = false,
            formatType = mockedMdocMdlFormat.docType
        ),
        ScopedDocumentDomain(
            name = mockedAgeVerificationDocName,
            configurationId = mockedConfigIssuerId,
            credentialIssuerId = mockedIssuerId,
            isPid = false,
            isAgeVerification = true,
            formatType = mockedMdocAgeVerificationFormat.docType
        ),
        ScopedDocumentDomain(
            name = mockedPhotoIdDocName,
            configurationId = mockedConfigIssuerId,
            credentialIssuerId = mockedIssuerId,
            isPid = false,
            isAgeVerification = false,
            formatType = mockedMdocPhotoIdFormat.docType
        )
    ).sortedBy { it.name.lowercase() }

internal val mockedOfferTxCodeFourDigits = TxCode(
    inputMode = TxCodeInputMode.NUMERIC,
    length = mockedTxCodeFourDigits
)

internal val mockedConfigNavigationTypePop = ConfigNavigation(navigationType = NavigationType.Pop)
internal val mockedConfigNavigationTypePush = ConfigNavigation(
    navigationType = NavigationType.PushRoute(
        route = LandingScreens.Landing.screenRoute,
        popUpToRoute = IssuanceScreens.AddDocument.screenRoute
    )
)
internal val mockedConfigNavigationTypePopToScreen = ConfigNavigation(
    navigationType = NavigationType.PopTo(
        screen = LandingScreens.Landing
    )
)

internal val mockedMdocPidClaims = listOf(
    createMdocClaimListItem(mockedPidId, "age_birth_year", "1985"),
    createMdocClaimListItem(mockedPidId, "age_over_18", "yes"),
    createMdocClaimListItem(mockedPidId, "age_over_65", "no"),
    createMdocClaimListItem(mockedPidId, "birth_city", "KATRINEHOLM"),
    createMdocClaimListItem(mockedPidId, "expiry_date", "30 Mar 2050"),
    createMdocClaimListItem(mockedPidId, "family_name", "ANDERSSON"),
    createMdocClaimListItem(mockedPidId, "gender", "Male"),
    createMdocClaimListItem(mockedPidId, "given_name", "JAN"),
)

internal val mockedSdJwtPidClaims = listOf(
    ExpandableListItemUi.SingleListItem(
        header = ListItemDataUi(
            itemId = "$mockedSdJwtPidId,age_birth_year",
            overlineText = "age_birth_year",
            mainContentData = ListItemMainContentDataUi.Text("1985")
        )
    ),
    ExpandableListItemUi.NestedListItem(
        header = ListItemDataUi(
            itemId = "$mockedSdJwtPidId,age_equal_or_over",
            mainContentData = ListItemMainContentDataUi.Text("age_equal_or_over"),
        ),
        nestedItems = listOf(
            ExpandableListItemUi.SingleListItem(
                header = ListItemDataUi(
                    itemId = "$mockedSdJwtPidId,age_equal_or_over,18",
                    overlineText = "18",
                    mainContentData = ListItemMainContentDataUi.Text("true")
                )
            ),
            ExpandableListItemUi.SingleListItem(
                header = ListItemDataUi(
                    itemId = "$mockedSdJwtPidId,age_equal_or_over,65",
                    overlineText = "65",
                    mainContentData = ListItemMainContentDataUi.Text("unset")
                )
            )
        ),
        isExpanded = true
    ),
    ExpandableListItemUi.SingleListItem(
        header = ListItemDataUi(
            itemId = "$mockedSdJwtPidId,birth_date",
            overlineText = "birth_date",
            mainContentData = ListItemMainContentDataUi.Text("30 Mar 1985")
        )
    ),
    ExpandableListItemUi.SingleListItem(
        header = ListItemDataUi(
            itemId = "$mockedSdJwtPidId,exp",
            overlineText = "exp",
            mainContentData = ListItemMainContentDataUi.Text(text = "1755730800")
        )
    ),
    ExpandableListItemUi.SingleListItem(
        header = ListItemDataUi(
            itemId = "$mockedSdJwtPidId,family_name",
            overlineText = "family_name",
            mainContentData = ListItemMainContentDataUi.Text("ANDERSSON")
        )
    ),
    ExpandableListItemUi.SingleListItem(
        header = ListItemDataUi(
            itemId = "$mockedSdJwtPidId,given_name",
            overlineText = "given_name",
            mainContentData = ListItemMainContentDataUi.Text("JAN")
        )
    ),
    ExpandableListItemUi.SingleListItem(
        header = ListItemDataUi(
            itemId = "$mockedSdJwtPidId,iat",
            overlineText = "iat",
            mainContentData = ListItemMainContentDataUi.Text(text = "1747954800")
        )
    ),
    ExpandableListItemUi.SingleListItem(
        header = ListItemDataUi(
            itemId = "$mockedSdJwtPidId,issuing_authority",
            overlineText = "issuing_authority",
            mainContentData = ListItemMainContentDataUi.Text(text = "Test PID issuer")
        )
    ),
    ExpandableListItemUi.SingleListItem(
        header = ListItemDataUi(
            itemId = "$mockedSdJwtPidId,issuing_country",
            overlineText = "issuing_country",
            mainContentData = ListItemMainContentDataUi.Text("FC")
        )
    ),
    ExpandableListItemUi.NestedListItem(
        header = ListItemDataUi(
            itemId = "$mockedSdJwtPidId,$mockedUuid",
            overlineText = null,
            mainContentData = ListItemMainContentDataUi.Text("nationalities"),
        ),
        nestedItems = listOf(
            ExpandableListItemUi.SingleListItem(
                header = ListItemDataUi(
                    itemId = "$mockedSdJwtPidId,nationalities",
                    overlineText = "nationalities",
                    mainContentData = ListItemMainContentDataUi.Text("SE")
                )
            )
        ),
        isExpanded = true
    ),
    ExpandableListItemUi.NestedListItem(
        header = ListItemDataUi(
            itemId = "$mockedSdJwtPidId,place_of_birth",
            overlineText = null,
            mainContentData = ListItemMainContentDataUi.Text("place_of_birth"),
        ),
        nestedItems = listOf(
            ExpandableListItemUi.SingleListItem(
                header = ListItemDataUi(
                    itemId = "$mockedSdJwtPidId,place_of_birth,locality",
                    overlineText = "locality",
                    mainContentData = ListItemMainContentDataUi.Text("KATRINEHOLM")
                )
            )
        ),
        isExpanded = true
    ),
)

private fun createMdocClaimListItem(docId: String, claimIdentifier: String, value: String) =
    ExpandableListItemUi.SingleListItem(
        header = ListItemDataUi(
            itemId = "$docId,$claimIdentifier",
            overlineText = claimIdentifier,
            mainContentData = ListItemMainContentDataUi.Text(value)
        )
    )