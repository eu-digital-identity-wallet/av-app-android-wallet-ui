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

package eu.europa.ec.issuancefeature.interactor

import eu.europa.ec.businesslogic.provider.UuidProvider
import eu.europa.ec.corelogic.controller.WalletCoreDocumentsController
import eu.europa.ec.eudi.wallet.document.IssuedDocument
import eu.europa.ec.issuancefeature.util.mockedErrorDescription
import eu.europa.ec.issuancefeature.util.mockedMdocPidClaims
import eu.europa.ec.issuancefeature.util.mockedSdJwtPidClaims
import eu.europa.ec.issuancefeature.util.mockedSuccessDescription
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.testfeature.util.StringResourceProviderMocker.mockIssuerName
import eu.europa.ec.testfeature.util.StringResourceProviderMocker.mockTransformToDocumentDetailsDomainStrings
import eu.europa.ec.testfeature.util.StringResourceProviderMocker.mockTransformToUiItemsStrings
import eu.europa.ec.testfeature.util.getMockedMdlWithBasicFields
import eu.europa.ec.testfeature.util.getMockedPidWithBasicFields
import eu.europa.ec.testfeature.util.getMockedPidWithBasicFieldsAndMetadata
import eu.europa.ec.testfeature.util.getMockedSdJwtPidWithBasicFields
import eu.europa.ec.testfeature.util.mockedDefaultLocale
import eu.europa.ec.testfeature.util.mockedGenericErrorMessage
import eu.europa.ec.testfeature.util.mockedIssuerLogo
import eu.europa.ec.testfeature.util.mockedIssuerName
import eu.europa.ec.testfeature.util.mockedPidId
import eu.europa.ec.testfeature.util.mockedSdJwtPidId
import eu.europa.ec.testfeature.util.mockedUuid
import eu.europa.ec.testlogic.extension.runFlowTest
import eu.europa.ec.testlogic.extension.runTest
import eu.europa.ec.testlogic.rule.CoroutineTestRule
import eu.europa.ec.uilogic.component.ListItemDataUi
import eu.europa.ec.uilogic.component.ListItemMainContentDataUi
import eu.europa.ec.uilogic.component.RelyingPartyDataUi
import eu.europa.ec.uilogic.component.content.ContentHeaderConfig
import eu.europa.ec.uilogic.component.wrap.ExpandableListItemUi
import junit.framework.TestCase.assertEquals
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mock
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.whenever
import java.net.URI

class TestDocumentIssuanceSuccessInteractor {

    @get:Rule
    val coroutineRule = CoroutineTestRule(testDispatcher = UnconfinedTestDispatcher())

    @Mock
    private lateinit var walletCoreDocumentsController: WalletCoreDocumentsController

    @Mock
    private lateinit var resourceProvider: ResourceProvider

    @Mock
    private lateinit var uuidProvider: UuidProvider

    private lateinit var interactor: DocumentIssuanceSuccessInteractor

    private lateinit var closeable: AutoCloseable

    @Before
    fun before() {
        closeable = MockitoAnnotations.openMocks(this)

        interactor = DocumentIssuanceSuccessInteractorImpl(
            resourceProvider = resourceProvider,
            uuidProvider = uuidProvider,
            walletCoreDocumentsController = walletCoreDocumentsController
        )

        whenever(resourceProvider.genericErrorMessage()).thenReturn(mockedGenericErrorMessage)
        whenever(resourceProvider.getLocale()).thenReturn(mockedDefaultLocale)

        mockIssuerName(resourceProvider = resourceProvider, name = mockedIssuerName)
        mockTransformToUiItemsStrings(
            resourceProvider = resourceProvider,
        )
    }

    @After
    fun after() {
        closeable.close()
    }

    // region getUiItems

    // Case 1:
    // When getUiItems() is called with a list containing one DocumentId (MsoMdoc):
    // walletCoreDocumentsController.getDocumentById() returns a valid IssuedDocument,
    // The document has issuer metadata (name and logo) and valid claims.

    //  Case 1 Expected Result:
    // 	DocumentIssuanceSuccessInteractorGetUiItemsPartialState.Success is emitted, with:
    // 	documentsUi: A list containing one ExpandableListItem.NestedListItemDataUi with document name and mapped claims,
    // 	headerConfig: Includes the issuer’s name.

    @Test
    fun `Given Case 1, When getUiItems is called, Then Success state with full document UI and header config is returned`() {
        coroutineRule.runTest {
            // Given
            mockHeaderConfigDescription(isErrorCase = false)
            mockTransformToDocumentDetailsDomainStrings(resourceProvider)

            val mockedPidWithBasicFields = getMockedPidWithBasicFields()
            mockGetDocumentByIdCall(response = mockedPidWithBasicFields)

            // When
            interactor.getUiItems(
                documentIds = listOf(mockedPidId)
            ).runFlowTest {
                // Then
                assertEquals(
                    DocumentIssuanceSuccessInteractorGetUiItemsPartialState.Success(
                        documentsUi = listOf(
                            ExpandableListItemUi.NestedListItem(
                                header = ListItemDataUi(
                                    itemId = mockedPidId,
                                    mainContentData = ListItemMainContentDataUi.Text(text = mockedPidWithBasicFields.name),
                                ),
                                nestedItems = mockedMdocPidClaims,
                                isExpanded = true
                            )
                        ),
                        headerConfig = ContentHeaderConfig(
                            description = mockedSuccessDescription,
                            relyingPartyData = RelyingPartyDataUi(
                                name = mockedIssuerName,
                                logo = null,
                                isVerified = false
                            )
                        ),
                    ),
                    awaitItem()
                )
            }
        }
    }

    // Case 2:
    // When getUiItems() is called with a list containing one DocumentId (SdJwt):
    // walletCoreDocumentsController.getDocumentById() returns a valid IssuedDocument,
    // The document has issuer metadata (name and logo) and valid claims.

    //  Case 2 Expected Result:
    // 	DocumentIssuanceSuccessInteractorGetUiItemsPartialState.Success is emitted, with:
    // 	documentsUi: A list containing one ExpandableListItem.NestedListItemDataUi with document name and mapped claims

    @Test
    fun `Given Case 2, When getUiItems is called, Then Success state with full document UI is returned`() {
        coroutineRule.runTest {
            // Given
            mockHeaderConfigDescription(isErrorCase = false)
            mockProvideUuid()
            mockTransformToDocumentDetailsDomainStrings(resourceProvider)

            val mockedSdJwtPidWithBasicFields = getMockedSdJwtPidWithBasicFields()
            mockGetDocumentByIdCall(response = mockedSdJwtPidWithBasicFields)

            // When
            interactor.getUiItems(
                documentIds = listOf(mockedSdJwtPidId)
            ).runFlowTest {
                // Then
                assertEquals(
                    DocumentIssuanceSuccessInteractorGetUiItemsPartialState.Success(
                        headerConfig = ContentHeaderConfig(
                            description = mockedSuccessDescription,
                            relyingPartyData = RelyingPartyDataUi(
                                name = mockedIssuerName,
                                logo = null,
                                isVerified = false
                            )
                        ),
                        documentsUi = listOf(
                            ExpandableListItemUi.NestedListItem(
                                header = ListItemDataUi(
                                    itemId = mockedSdJwtPidId,
                                    mainContentData = ListItemMainContentDataUi.Text(text = mockedSdJwtPidWithBasicFields.name),
                                ),
                                nestedItems = mockedSdJwtPidClaims,
                                isExpanded = true
                            )
                        )
                    ),
                    awaitItem()
                )
            }
        }
    }


    // Case 3:
    // When getUiItems() is called with multiple DocumentIds, one of type MsoMdoc and one of type SD-JWT:
    // One document is fetched successfully,
    // Another document throws an exception from getDocumentById().

    // Case 3 Expected Result:
    // DocumentIssuanceSuccessInteractorGetUiItemsPartialState.Success is emitted, with:
    // documentsUi: A list containing only the successfully retrieved document

    @Test
    fun `Given Case 3, When getUiItems is called, Then Success state with one document UI is returned`() {
        coroutineRule.runTest {
            // Given
            mockHeaderConfigDescription(isErrorCase = false)
            mockTransformToDocumentDetailsDomainStrings(resourceProvider)

            val mockedPidWithBasicFields = getMockedPidWithBasicFields()
            mockGetDocumentByIdCall(response = mockedPidWithBasicFields)
            mockSdJwtGetDocumentByIdCall(docId = mockedSdJwtPidId, response = null)

            // When
            interactor.getUiItems(
                documentIds = listOf(mockedPidWithBasicFields.id, mockedSdJwtPidId)
            ).runFlowTest {
                // Then
                assertEquals(
                    DocumentIssuanceSuccessInteractorGetUiItemsPartialState.Success(
                        documentsUi = listOf(
                            ExpandableListItemUi.NestedListItem(
                                header = ListItemDataUi(
                                    itemId = mockedPidWithBasicFields.id,
                                    mainContentData = ListItemMainContentDataUi.Text(text = mockedPidWithBasicFields.name),
                                ),
                                nestedItems = mockedMdocPidClaims,
                                isExpanded = true
                            )
                        ),
                        headerConfig = ContentHeaderConfig(
                            description = mockedSuccessDescription,
                            relyingPartyData = RelyingPartyDataUi(
                                name = mockedIssuerName,
                                logo = null,
                                isVerified = false
                            )
                        ),
                    ),
                    awaitItem()
                )
            }
        }
    }

    // Case 4:
    // When getUiItems() is called with multiple DocumentIds,
    // and all calls to walletCoreDocumentsController.getDocumentById() throw exceptions.

    // Case 4 Expected Result:
    // DocumentIssuanceSuccessInteractorGetUiItemsPartialState.Success is emitted, with:
    // documentsUi: An empty list

    @Test
    fun `Given Case 4, When getUiItems is called, Then Success state with empty list is returned`() {
        coroutineRule.runTest {
            // Given
            mockHeaderConfigDescription(isErrorCase = true)
            mockTransformToDocumentDetailsDomainStrings(resourceProvider)
            mockGetDocumentByIdCall(response = null)
            mockSdJwtGetDocumentByIdCall(docId = mockedSdJwtPidId, response = null)

            // When
            interactor.getUiItems(
                documentIds = listOf(getMockedMdlWithBasicFields().id, mockedSdJwtPidId)
            ).runFlowTest {
                // Then
                assertEquals(
                    DocumentIssuanceSuccessInteractorGetUiItemsPartialState.Success(
                        documentsUi = listOf(),
                        headerConfig = ContentHeaderConfig(
                            description = mockedErrorDescription,
                            relyingPartyData = RelyingPartyDataUi(
                                name = mockedIssuerName,
                                logo = null,
                                isVerified = false
                            )
                        ),
                    ),
                    awaitItem()
                )
            }
        }
    }

    // Case 5:
    // When getUiItems() is called with an empty list.

    // Case 5 Expected Result:
    // DocumentIssuanceSuccessInteractorGetUiItemsPartialState.Success is emitted, with:
    // documentsUi: An empty list

    @Test
    fun `Given Case 5, When getUiItems is called, Then Success state with empty list is returned`() {
        coroutineRule.runTest {
            // Given
            mockHeaderConfigDescription(isErrorCase = true)
            mockTransformToDocumentDetailsDomainStrings(resourceProvider)
            mockGetDocumentByIdCall(response = null)
            mockSdJwtGetDocumentByIdCall(docId = mockedSdJwtPidId, response = null)

            // When
            interactor.getUiItems(
                documentIds = listOf()
            ).runFlowTest {
                // Then
                assertEquals(
                    DocumentIssuanceSuccessInteractorGetUiItemsPartialState.Success(
                        documentsUi = listOf(),
                        headerConfig = ContentHeaderConfig(
                            description = mockedErrorDescription,
                            relyingPartyData = RelyingPartyDataUi(
                                name = mockedIssuerName,
                                logo = null,
                                isVerified = false
                            )
                        ),
                    ),
                    awaitItem()
                )
            }
        }
    }

    // Case 6:
    // When getUiItems() is called with documents that are successfully fetched.

    // Case 6 Expected Result:
    // DocumentIssuanceSuccessInteractorGetUiItemsPartialState.Success is emitted, with:
    // documentsUi: A list of all successfully fetched documents.

    @Test
    fun `Given Case 6, When getUiItems is called, Then Success state with full document UI list is returned`() {
        coroutineRule.runTest {
            // Given
            mockHeaderConfigDescription(isErrorCase = false)
            mockTransformToDocumentDetailsDomainStrings(resourceProvider)
            mockProvideUuid()

            val mockedPidWithBasicFields = getMockedPidWithBasicFields()
            mockGetDocumentByIdCall(response = mockedPidWithBasicFields)

            val mockedSdJwtPidWithBasicFields = getMockedSdJwtPidWithBasicFields()
            mockSdJwtGetDocumentByIdCall(
                docId = mockedSdJwtPidId,
                response = mockedSdJwtPidWithBasicFields
            )

            // When
            interactor.getUiItems(
                documentIds = listOf(mockedPidId, mockedSdJwtPidId)
            ).runFlowTest {
                // Then
                assertEquals(
                    DocumentIssuanceSuccessInteractorGetUiItemsPartialState.Success(
                        headerConfig = ContentHeaderConfig(
                            description = mockedSuccessDescription,
                            relyingPartyData = RelyingPartyDataUi(
                                name = mockedIssuerName,
                                logo = null,
                                isVerified = false
                            )
                        ),
                        documentsUi = listOf(
                            ExpandableListItemUi.NestedListItem(
                                header = ListItemDataUi(
                                    itemId = mockedPidId,
                                    mainContentData = ListItemMainContentDataUi.Text(text = mockedPidWithBasicFields.name),
                                ),
                                nestedItems = mockedMdocPidClaims,
                                isExpanded = true
                            ),
                            ExpandableListItemUi.NestedListItem(
                                header = ListItemDataUi(
                                    itemId = mockedSdJwtPidId,
                                    mainContentData = ListItemMainContentDataUi.Text(text = mockedSdJwtPidWithBasicFields.name),
                                ),
                                nestedItems = mockedSdJwtPidClaims,
                                isExpanded = true
                            )
                        )
                    ),
                    awaitItem()
                )
            }
        }
    }

    // Case 7:
    // When getUiItems() is called, and an unexpected exception occurs during the process

    // Case 7 Expected Result:
    // DocumentIssuanceSuccessInteractorGetUiItemsPartialState.Failed is emitted, containing:
    // errorMessage: The localized message from the thrown exception.

    @Test
    fun `Given Case 7, When getUiItems is called, Then Failure state is returned`() {
        coroutineRule.runTest {
            // Given
            val specificErrorMessage = "Document retrieval failed!"
            val expectedException = RuntimeException(specificErrorMessage)
            whenever(resourceProvider.getLocale()).thenThrow(expectedException)

            // When
            interactor.getUiItems(
                documentIds = listOf(mockedPidId, mockedSdJwtPidId)
            ).runFlowTest {
                // Then
                assertEquals(
                    DocumentIssuanceSuccessInteractorGetUiItemsPartialState.Failed(
                        errorMessage = expectedException.localizedMessage!!
                    ),
                    awaitItem()
                )
            }
        }
    }

    // Case 8:
    // When getUiItems() is called with a list containing one DocumentId with valid metadata:
    // walletCoreDocumentsController.getDocumentById() returns a valid IssuedDocument,
    // The document has issuer metadata (name and logo) and valid claims.

    //  Case 8 Expected Result:
    // 	DocumentIssuanceSuccessInteractorGetUiItemsPartialState.Success is emitted, with:
    // 	documentsUi: A list containing one ExpandableListItem.NestedListItemDataUi with document name and mapped claims,
    // 	headerConfig: Includes the issuer’s name and logo.

    @Test
    fun `Given Case 8, When getUiItems is called, Then Success state is returned`() {
        coroutineRule.runTest {
            // Given
            mockHeaderConfigDescription(isErrorCase = false)
            mockTransformToDocumentDetailsDomainStrings(resourceProvider)

            val mockedPidWithBasicFieldsAndMetadata = getMockedPidWithBasicFieldsAndMetadata()
            mockGetDocumentByIdCall(response = mockedPidWithBasicFieldsAndMetadata)

            // When
            interactor.getUiItems(
                documentIds = listOf(mockedPidId)
            ).runFlowTest {
                // Then
                assertEquals(
                    DocumentIssuanceSuccessInteractorGetUiItemsPartialState.Success(
                        documentsUi = listOf(
                            ExpandableListItemUi.NestedListItem(
                                header = ListItemDataUi(
                                    itemId = mockedPidId,
                                    mainContentData = ListItemMainContentDataUi.Text(text = mockedPidWithBasicFieldsAndMetadata.name),
                                ),
                                nestedItems = mockedMdocPidClaims,
                                isExpanded = true
                            )
                        ),
                        headerConfig = ContentHeaderConfig(
                            description = mockedSuccessDescription,
                            relyingPartyData = RelyingPartyDataUi(
                                name = mockedIssuerName,
                                logo = URI.create(mockedIssuerLogo),
                                isVerified = false
                            )
                        ),
                    ),
                    awaitItem()
                )
            }
        }
    }

    // endregion

    //region Mock Calls

    private fun mockHeaderConfigDescription(
        isErrorCase: Boolean
    ) {
        val description = if (isErrorCase) mockedErrorDescription else mockedSuccessDescription

        if (isErrorCase) {
            whenever(resourceProvider.getString(R.string.issuance_success_header_description_when_error))
                .thenReturn(description)
        } else {
            whenever(resourceProvider.getString(R.string.issuance_success_header_description))
                .thenReturn(description)
        }
    }

    private fun mockProvideUuid() {
        whenever(uuidProvider.provideUuid())
            .thenReturn(mockedUuid)
    }

    private fun mockGetDocumentByIdCall(response: IssuedDocument?) {
        whenever(walletCoreDocumentsController.getDocumentById(anyString()))
            .thenReturn(response)
    }

    private fun mockSdJwtGetDocumentByIdCall(docId: String, response: IssuedDocument?) {
        whenever(walletCoreDocumentsController.getDocumentById(docId))
            .thenReturn(response)
    }

    //endregion
}