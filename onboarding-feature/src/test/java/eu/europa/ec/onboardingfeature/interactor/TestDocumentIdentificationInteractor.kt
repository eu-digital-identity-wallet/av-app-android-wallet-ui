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

package eu.europa.ec.onboardingfeature.interactor

import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.testfeature.util.mockedGenericErrorMessage
import junit.framework.TestCase.assertEquals
import kotlin.time.Clock
import kotlin.time.Instant
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.mockito.Mock
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.whenever

class TestDocumentIdentificationInteractor {

    @Mock
    private lateinit var resourceProvider: ResourceProvider

    @Mock
    private lateinit var logController: LogController

    private lateinit var interactor: DocumentIdentificationInteractor

    private lateinit var closeable: AutoCloseable

    // Fixed clock for testing - set to January 1, 2025
    private val testClock = object : Clock {
        override fun now(): Instant = Instant.parse("2025-01-01T00:00:00Z")
    }

    @Before
    fun before() {
        closeable = MockitoAnnotations.openMocks(this)

        interactor = DocumentIdentificationInteractorImpl(
            resourceProvider = resourceProvider,
            logController = logController,
            clock = testClock
        )

        whenever(resourceProvider.genericErrorMessage()).thenReturn(mockedGenericErrorMessage)
    }

    @After
    fun after() {
        closeable.close()
    }

    //region validateDocument

    // Case 1: Valid document with adult user
    @Test
    fun `Given valid document with user over 18, When validateDocument is called, Then Success state is returned`() {
        // Given
        val dateOfBirth = "03/30/1990" // 34 years old in 2025
        val expiryDate = "12/31/2030" // Not expired

        // When
        val result = interactor.validateDocument(dateOfBirth, expiryDate)

        // Then
        assertEquals(DocumentValidationState.Success, result)
    }

    // Case 2: User is exactly 18 years old
    @Test
    fun `Given user is exactly 18 years old, When validateDocument is called, Then Success state is returned`() {
        // Given
        val dateOfBirth = "01/01/2007" // Exactly 18 years old on Jan 1, 2025
        val expiryDate = "12/31/2030"

        // When
        val result = interactor.validateDocument(dateOfBirth, expiryDate)

        // Then
        assertEquals(DocumentValidationState.Success, result)
    }

    // Case 3: User is under 18 years old
    @Test
    fun `Given user is under 18 years old, When validateDocument is called, Then Failure state is returned`() {
        // Given
        val dateOfBirth = "03/30/2010" // 14 years old in 2025
        val expiryDate = "12/31/2030"
        val expectedError = "User must be at least 18 years old"
        whenever(resourceProvider.getString(R.string.passport_validation_error_underage))
            .thenReturn(expectedError)

        // When
        val result = interactor.validateDocument(dateOfBirth, expiryDate)

        // Then
        assert(result is DocumentValidationState.Failure)
        assertEquals(expectedError, (result as DocumentValidationState.Failure).error)
    }

    // Case 4: Document has expired
    @Test
    fun `Given document has expired, When validateDocument is called, Then Failure state is returned`() {
        // Given
        val dateOfBirth = "03/30/1990"
        val expiryDate = "12/31/2020" // Expired
        val expectedError = "Document has expired"
        whenever(resourceProvider.getString(R.string.passport_validation_error_expired))
            .thenReturn(expectedError)

        // When
        val result = interactor.validateDocument(dateOfBirth, expiryDate)

        // Then
        assert(result is DocumentValidationState.Failure)
        assertEquals(expectedError, (result as DocumentValidationState.Failure).error)
    }

    // Case 5: Document expires today (should be valid)
    @Test
    fun `Given document expires today, When validateDocument is called, Then Success state is returned`() {
        // Given
        val dateOfBirth = "03/30/1990"
        val expiryDate = "01/01/2025" // Expires today

        // When
        val result = interactor.validateDocument(dateOfBirth, expiryDate)

        // Then
        assertEquals(DocumentValidationState.Success, result)
    }

    // Case 6: Invalid date format
    @Test
    fun `Given invalid date format, When validateDocument is called, Then Failure state is returned`() {
        // Given
        val dateOfBirth = "invalid-date"
        val expiryDate = "12/31/2030"

        // When
        val result = interactor.validateDocument(dateOfBirth, expiryDate)

        // Then
        assert(result is DocumentValidationState.Failure)
        assertEquals(mockedGenericErrorMessage, (result as DocumentValidationState.Failure).error)
    }

    // Case 7: User is 17 years and 364 days old (just under 18)
    @Test
    fun `Given user is just under 18 years old, When validateDocument is called, Then Failure state is returned`() {
        // Given
        val dateOfBirth = "01/02/2007" // 17 years and 364 days old on Jan 1, 2025
        val expiryDate = "12/31/2030"
        val expectedError = "User must be at least 18 years old"
        whenever(resourceProvider.getString(R.string.passport_validation_error_underage))
            .thenReturn(expectedError)

        // When
        val result = interactor.validateDocument(dateOfBirth, expiryDate)

        // Then
        assert(result is DocumentValidationState.Failure)
        assertEquals(expectedError, (result as DocumentValidationState.Failure).error)
    }

    // Case 8: Document expired yesterday
    @Test
    fun `Given document expired yesterday, When validateDocument is called, Then Failure state is returned`() {
        // Given
        val dateOfBirth = "03/30/1990"
        val expiryDate = "12/31/2024" // Expired yesterday
        val expectedError = "Document has expired"
        whenever(resourceProvider.getString(R.string.passport_validation_error_expired))
            .thenReturn(expectedError)

        // When
        val result = interactor.validateDocument(dateOfBirth, expiryDate)

        // Then
        assert(result is DocumentValidationState.Failure)
        assertEquals(expectedError, (result as DocumentValidationState.Failure).error)
    }

    // Case 9: Empty date strings
    @Test
    fun `Given empty date strings, When validateDocument is called, Then Failure state is returned`() {
        // Given
        val dateOfBirth = ""
        val expiryDate = ""

        // When
        val result = interactor.validateDocument(dateOfBirth, expiryDate)

        // Then
        assert(result is DocumentValidationState.Failure)
        assertEquals(mockedGenericErrorMessage, (result as DocumentValidationState.Failure).error)
    }
    //endregion
}
