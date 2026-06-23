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

package eu.europa.ec.landingfeature.interactor

import eu.europa.ec.businesslogic.provider.UuidProvider
import eu.europa.ec.commonfeature.util.transformPathsToDomainClaims
import eu.europa.ec.corelogic.controller.WalletCoreDocumentsController
import eu.europa.ec.corelogic.extension.toClaimPaths
import eu.europa.ec.eudi.wallet.document.format.SdJwtVcClaim
import eu.europa.ec.eudi.wallet.document.format.SdJwtVcData
import eu.europa.ec.landingfeature.interactor.LandingPageInteractor.GetAgeCredentialPartialState
import eu.europa.ec.landingfeature.model.AgeCredentialUi
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.testfeature.util.copy
import eu.europa.ec.testfeature.util.getMockedEmptyPid
import eu.europa.ec.testfeature.util.getMockedMainPid
import eu.europa.ec.testfeature.util.mockedDefaultLocale
import eu.europa.ec.testfeature.util.mockedExceptionWithMessage
import eu.europa.ec.testfeature.util.mockedExceptionWithNoMessage
import eu.europa.ec.testfeature.util.mockedGenericErrorMessage
import eu.europa.ec.testfeature.util.mockedPlainFailureMessage
import org.mockito.kotlin.mock
import eu.europa.ec.testlogic.extension.runFlowTest
import eu.europa.ec.testlogic.extension.runTest
import eu.europa.ec.testlogic.rule.CoroutineTestRule
import junit.framework.TestCase.assertEquals
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.mockito.Mock
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.any
import org.mockito.kotlin.whenever

class TestLandingPageInteractor {

    @get:Rule
    val coroutineRule = CoroutineTestRule()

    @Mock
    private lateinit var walletCoreDocumentsController: WalletCoreDocumentsController

    @Mock
    private lateinit var uuidProvider: UuidProvider

    @Mock
    private lateinit var resourceProvider: ResourceProvider

    private lateinit var interactor: LandingPageInteractor

    private lateinit var closeable: AutoCloseable

    @Before
    fun before() {
        closeable = MockitoAnnotations.openMocks(this)

        interactor = LandingPageInteractorImpl(
            walletCoreDocumentsController = walletCoreDocumentsController,
            resourceProvider = resourceProvider,
            uuidProvider = uuidProvider
        )

        whenever(resourceProvider.genericErrorMessage()).thenReturn(mockedGenericErrorMessage)
        whenever(resourceProvider.getString(R.string.landing_screen_no_age_credential_found)).thenReturn(
            mockedPlainFailureMessage
        )
        whenever(resourceProvider.getLocale()).thenReturn(mockedDefaultLocale)
    }

    @After
    fun after() {
        closeable.close()
    }

    //region getAgeCredential

    // Case 1:
    // 1. walletCoreDocumentsController.getAllDocuments() returns a list containing an age credential document.
    // 2. The document is successfully transformed into an AgeCredentialUi.

    // Case 1 Expected Result:
    // LandingPageInteractorGetAgeCredentialPartialState.Success state with the transformed AgeCredentialUi.
    @Test
    fun `Given Case 1, When getAgeCredential is called, Then Case 1 Expected Result is returned`() {
        coroutineRule.runTest {
            val mockedDoc = getMockedMainPid().copy(availableCredentials = 2)

            // Given
            whenever(walletCoreDocumentsController.getAllIssuedDocuments())
                .thenReturn(listOf(mockedDoc))

            whenever(resourceProvider.getString(any())).thenReturn("mockedString")

            // When
            interactor.getAgeCredential().runFlowTest {
                // Then
                val expectedState = GetAgeCredentialPartialState.Success(
                    ageCredentialUi = AgeCredentialUi(
                        docId = mockedDoc.id,
                        claims = transformPathsToDomainClaims(
                            paths = mockedDoc.data.claims.flatMap { it.toClaimPaths() },
                            claims = mockedDoc.data.claims,
                            resourceProvider = resourceProvider,
                            uuidProvider = uuidProvider
                        ),
                        credentialCount = 2,
                        ageThreshold = 21,
                    )
                )
                assertEquals(expectedState, awaitItem())
            }
        }
    }

    // Case 2:
    // 1. walletCoreDocumentsController.getAllDocuments() returns an empty list.

    // Case 2 Expected Result:
    // LandingPageInteractorGetAgeCredentialPartialState.Failure state with the "no age credential found" message.
    @Test
    fun `Given Case 2, When getAgeCredential is called, Then Case 2 Expected Result is returned`() {
        coroutineRule.runTest {
            // Given
            whenever(walletCoreDocumentsController.getAllIssuedDocuments())
                .thenReturn(emptyList())

            // When
            interactor.getAgeCredential().runFlowTest {
                // Then
                assertEquals(
                    GetAgeCredentialPartialState.Failure(
                        error = mockedPlainFailureMessage
                    ),
                    awaitItem()
                )
            }
        }
    }

    // Case 3:
    // 1. walletCoreDocumentsController.getAllDocuments() throws an exception with a message.

    // Case 3 Expected Result:
    // LandingPageInteractorGetAgeCredentialPartialState.Failure state with the exception's localized message.
    @Test
    fun `Given Case 3, When getAgeCredential is called, Then Case 3 Expected Result is returned`() {
        coroutineRule.runTest {
            // Given
            whenever(walletCoreDocumentsController.getAllIssuedDocuments())
                .thenThrow(mockedExceptionWithMessage)

            // When
            interactor.getAgeCredential().runFlowTest {
                // Then
                assertEquals(
                    GetAgeCredentialPartialState.Failure(
                        error = mockedExceptionWithMessage.localizedMessage!!
                    ),
                    awaitItem()
                )
            }
        }
    }

    // Case 4:
    // 1. walletCoreDocumentsController.getAllDocuments() throws an exception with no message.

    // Case 4 Expected Result:
    // LandingPageInteractorGetAgeCredentialPartialState.Failure state with the generic error message.
    @Test
    fun `Given Case 4, When getAgeCredential is called, Then Case 4 Expected Result is returned`() {
        coroutineRule.runTest {
            // Given
            whenever(walletCoreDocumentsController.getAllIssuedDocuments())
                .thenThrow(mockedExceptionWithNoMessage)

            // When
            interactor.getAgeCredential().runFlowTest {
                // Then
                assertEquals(
                    GetAgeCredentialPartialState.Failure(
                        error = mockedGenericErrorMessage
                    ),
                    awaitItem()
                )
            }
        }
    }

    // Case 5:
    // 1. walletCoreDocumentsController.getAllIssuedDocuments() returns a document with no claims.
    // 2. No age_over_* claim with a true value is found.

    // Case 5 Expected Result:
    // GetAgeCredentialPartialState.Success with ageThreshold = null.
    @Test
    fun `Given Case 5, When getAgeCredential is called, Then Case 5 Expected Result is returned`() {
        coroutineRule.runTest {
            val mockedDoc = getMockedEmptyPid().copy(availableCredentials = 2)

            // Given
            whenever(walletCoreDocumentsController.getAllIssuedDocuments())
                .thenReturn(listOf(mockedDoc))

            whenever(resourceProvider.getString(any())).thenReturn("mockedString")

            // When
            interactor.getAgeCredential().runFlowTest {
                // Then
                val expectedState = GetAgeCredentialPartialState.Success(
                    ageCredentialUi = AgeCredentialUi(
                        docId = mockedDoc.id,
                        claims = transformPathsToDomainClaims(
                            paths = mockedDoc.data.claims.flatMap { it.toClaimPaths() },
                            claims = mockedDoc.data.claims,
                            resourceProvider = resourceProvider,
                            uuidProvider = uuidProvider
                        ),
                        credentialCount = 2,
                        ageThreshold = null,
                    )
                )
                assertEquals(expectedState, awaitItem())
            }
        }
    }

    // Case 6:
    // 1. walletCoreDocumentsController.getAllIssuedDocuments() returns a document where the
    //    age_over_21 claim is itself an SdJwtVcClaim with non-empty children (i.e. a container node).
    // 2. flattenClaims must include the parent node itself so the threshold is not lost.

    // Case 6 Expected Result:
    // GetAgeCredentialPartialState.Success with ageThreshold = 21.
    @Test
    fun `Given Case 6, When getAgeCredential is called, Then Case 6 Expected Result is returned`() {
        coroutineRule.runTest {
            val ageClaim = SdJwtVcClaim(
                identifier = "age_over_21",
                value = true,
                rawValue = "true",
                issuerMetadata = null,
                selectivelyDisclosable = true,
                children = listOf(
                    SdJwtVcClaim(
                        identifier = "sub_claim",
                        value = null,
                        rawValue = "",
                        issuerMetadata = null,
                        selectivelyDisclosable = false,
                        children = emptyList()
                    )
                )
            )
            val mockedData = mock<SdJwtVcData>()
            whenever(mockedData.claims).thenReturn(listOf(ageClaim))

            val mockedDoc = getMockedMainPid().copy(
                data = mockedData,
                availableCredentials = 1
            )

            // Given
            whenever(walletCoreDocumentsController.getAllIssuedDocuments())
                .thenReturn(listOf(mockedDoc))

            whenever(resourceProvider.getString(any())).thenReturn("mockedString")

            // When
            interactor.getAgeCredential().runFlowTest {
                // Then
                val expectedState = GetAgeCredentialPartialState.Success(
                    ageCredentialUi = AgeCredentialUi(
                        docId = mockedDoc.id,
                        claims = transformPathsToDomainClaims(
                            paths = mockedData.claims.flatMap { it.toClaimPaths() },
                            claims = mockedData.claims,
                            resourceProvider = resourceProvider,
                            uuidProvider = uuidProvider
                        ),
                        credentialCount = 1,
                        ageThreshold = 21,
                    )
                )
                assertEquals(expectedState, awaitItem())
            }
        }
    }

    //endregion
}