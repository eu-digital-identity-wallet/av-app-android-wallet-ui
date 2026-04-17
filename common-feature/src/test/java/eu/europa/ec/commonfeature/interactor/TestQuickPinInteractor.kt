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

package eu.europa.ec.commonfeature.interactor

import eu.europa.ec.authenticationlogic.controller.storage.PinStorageController
import eu.europa.ec.authenticationlogic.controller.storage.PinValidationResult
import eu.europa.ec.businesslogic.validator.FormValidator
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.testfeature.util.mockedExceptionWithMessage
import eu.europa.ec.testfeature.util.mockedExceptionWithNoMessage
import eu.europa.ec.testfeature.util.mockedGenericErrorMessage
import eu.europa.ec.testlogic.extension.runFlowTest
import eu.europa.ec.testlogic.extension.runTest
import eu.europa.ec.testlogic.rule.CoroutineTestRule
import junit.framework.TestCase.assertEquals
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.mockito.Mock
import org.mockito.Mockito.anyString
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

class TestQuickPinInteractor {

    @get:Rule
    val coroutineRule = CoroutineTestRule()

    @Mock
    private lateinit var formValidator: FormValidator

    @Mock
    private lateinit var pinStorageController: PinStorageController

    @Mock
    private lateinit var resourceProvider: ResourceProvider

    private lateinit var interactor: QuickPinInteractor

    private lateinit var closeable: AutoCloseable

    @Before
    fun before() {
        closeable = MockitoAnnotations.openMocks(this)

        interactor = QuickPinInteractorImpl(
            formValidator = formValidator,
            pinStorageController = pinStorageController,
            resourceProvider = resourceProvider
        )

        whenever(resourceProvider.genericErrorMessage())
            .thenReturn(mockedGenericErrorMessage)
    }

    @After
    fun after() {
        closeable.close()
    }

    //region hasPin

    // Case 1:
    // pinStorageController.hasPin() returns false.
    @Test
    fun `Given Case 1, When hasPin is called, Then it returns false`() {
        // Given
        whenever(pinStorageController.hasPin())
            .thenReturn(false)

        // When
        val actual = interactor.hasPin()

        // Then
        val expected = false

        assertEquals(expected, actual)
        verify(pinStorageController, times(1))
            .hasPin()
    }

    // Case 2:
    // pinStorageController.hasPin() returns false.
    @Test
    fun `Given Case 2, When hasPin is called, Then it returns false`() {
        // Given
        whenever(pinStorageController.hasPin())
            .thenReturn(false)

        // When
        val actual = interactor.hasPin()

        // Then
        val expected = false

        assertEquals(expected, actual)
        verify(pinStorageController, times(1))
            .hasPin()
    }

    // Case 3:
    // pinStorageController.hasPin() returns true.
    @Test
    fun `Given Case 3, When hasPin is called, Then it returns true`() {
        // Given
        whenever(pinStorageController.hasPin())
            .thenReturn(true)

        // When
        val actual = interactor.hasPin()

        // Then
        val expected = true

        assertEquals(expected, actual)
        verify(pinStorageController, times(1))
            .hasPin()
    }
    //endregion

    //region setPin

    // Case 1:
    // isPinMatched returns Success.
    // pinStorageController.setPin() throws no errors.
    @Test
    fun `Given Case 1, When setPin is called, Then it returns Success`() {
        coroutineRule.runTest {
            // Given
            val mockedNewPin = mockedPin
            val mockedInitialPin = mockedPin

            // When
            interactor.setPin(
                newPin = mockedNewPin,
                initialPin = mockedInitialPin,
            ).runFlowTest {
                // Then
                assertEquals(
                    QuickPinInteractorSetPinPartialState.Success,
                    awaitItem()
                )
            }

            verify(pinStorageController, times(1))
                .setPin(pin = mockedPin)
        }
    }

    // Case 2:
    // isPinMatched returns Failed.
    @Test
    fun `Given Case 2, When setPin is called, Then it returns Failed with the appropriate error message`() {
        coroutineRule.runTest {
            // Given
            whenever(resourceProvider.getString(R.string.quick_pin_non_match))
                .thenReturn(mockedPinsDontMatchMessage)

            val mockedNewPin = mockedNewPin
            val mockedInitialPin = mockedInitialPin

            // When
            interactor.setPin(
                newPin = mockedNewPin,
                initialPin = mockedInitialPin,
            ).runFlowTest {
                // Then
                assertEquals(
                    QuickPinInteractorSetPinPartialState.Failed(
                        errorMessage = mockedPinsDontMatchMessage
                    ),
                    awaitItem()
                )

                verify(resourceProvider, times(1))
                    .getString(R.string.quick_pin_non_match)
            }
        }
    }

    // Case 3:
    // isPinMatched returns Success.
    // pinStorageController.setPin() throws an exception with a message.
    @Test
    fun `Given Case 3, When setPin is called, Then it returns Failed with exception's localized message`() {
        coroutineRule.runTest {
            // Given
            val mockedNewPin = mockedPin
            val mockedInitialPin = mockedPin
            whenever(pinStorageController.setPin(anyString()))
                .thenThrow(mockedExceptionWithMessage)

            // When
            interactor.setPin(
                newPin = mockedNewPin,
                initialPin = mockedInitialPin,
            ).runFlowTest {
                // Then
                assertEquals(
                    QuickPinInteractorSetPinPartialState.Failed(
                        errorMessage = mockedExceptionWithMessage.localizedMessage!!
                    ),
                    awaitItem()
                )
            }
        }
    }

    // Case 4:
    // isPinMatched returns Success.
    // pinStorageController.setPin() throws an exception with no message.
    @Test
    fun `Given Case 4, When setPin is called, Then it returns Failed with the generic error message`() {
        coroutineRule.runTest {
            // Given
            val mockedNewPin = mockedPin
            val mockedInitialPin = mockedPin
            whenever(pinStorageController.setPin(anyString()))
                .thenThrow(mockedExceptionWithNoMessage)

            // When
            interactor.setPin(
                newPin = mockedNewPin,
                initialPin = mockedInitialPin,
            ).runFlowTest {
                // Then
                assertEquals(
                    QuickPinInteractorSetPinPartialState.Failed(
                        errorMessage = mockedGenericErrorMessage
                    ),
                    awaitItem()
                )
            }
        }
    }
    //endregion

    //region changePin

    // Case 1:
    // pinStorageController.setPin() throws no errors.
    @Test
    fun `Given Case 1, When changePin is called, Then it returns Success`() {
        coroutineRule.runTest {

            // When
            interactor.changePin(
                newPin = mockedNewPin
            ).runFlowTest {
                // Then
                assertEquals(
                    QuickPinInteractorSetPinPartialState.Success,
                    awaitItem()
                )
            }
        }
    }

    // Case 2:
    // pinStorageController.setPin() throws an exception with a message.
    @Test
    fun `Given Case 2, When changePin is called, Then it returns Failed with exception's localized message`() {
        coroutineRule.runTest {
            // Given
            whenever(pinStorageController.setPin(mockedNewPin))
                .thenThrow(mockedExceptionWithMessage)

            // When
            interactor.changePin(
                newPin = mockedNewPin
            ).runFlowTest {
                // Then
                assertEquals(
                    QuickPinInteractorSetPinPartialState.Failed(
                        errorMessage = mockedExceptionWithMessage.localizedMessage!!
                    ),
                    awaitItem()
                )
            }
        }
    }

    // Case 3:
    // pinStorageController.setPin() throws an exception with no message.
    @Test
    fun `Given Case 3, When changePin is called, Then it returns Failed with the generic error message`() {
        coroutineRule.runTest {
            // Given
            whenever(pinStorageController.setPin(mockedNewPin))
                .thenThrow(mockedExceptionWithNoMessage)

            // When
            interactor.changePin(
                newPin = mockedNewPin
            ).runFlowTest {
                // Then
                assertEquals(
                    QuickPinInteractorSetPinPartialState.Failed(
                        errorMessage = mockedGenericErrorMessage
                    ),
                    awaitItem()
                )
            }
        }
    }
    //endregion

    //region isCurrentPinValid

    // Case 1:
    // pinStorageController.isPinValid() returns Success.
    @Test
    fun `Given Case 1, When isCurrentPinValid is called, Then it returns Success`() {
        coroutineRule.runTest {
            // Given
            whenever(pinStorageController.isPinValid(anyString()))
                .thenReturn(PinValidationResult.Success)

            // When
            interactor.isCurrentPinValid(
                pin = mockedPin
            ).runFlowTest {
                // Then
                assertEquals(
                    QuickPinInteractorPinValidPartialState.Success,
                    awaitItem()
                )
            }
        }
    }

    // Case 2:
    // pinStorageController.validatePinWithAttemptTracking() returns Failed.
    @Test
    fun `Given Case 2, When isCurrentPinValid is called, Then it returns Failed with the appropriate error message`() {
        coroutineRule.runTest {
            // Given
            whenever(pinStorageController.isPinValid(anyString()))
                .thenReturn(PinValidationResult.Failed(attemptsRemaining = 2))

            whenever(resourceProvider.getString(R.string.quick_pin_invalid_with_attempts, 2))
                .thenReturn(mockedInvalidPinMessage)

            // When
            interactor.isCurrentPinValid(
                pin = mockedNewPin
            ).runFlowTest {
                // Then
                assertEquals(
                    QuickPinInteractorPinValidPartialState.Failed(
                        errorMessage = mockedInvalidPinMessage,
                        attemptsRemaining = 2
                    ),
                    awaitItem()
                )

                verify(resourceProvider, times(1))
                    .getString(R.string.quick_pin_invalid_with_attempts, 2)
            }
        }
    }

    // Case 3:
    // pinStorageController.validatePinWithAttemptTracking() throws an exception with a message.
    @Test
    fun `Given Case 3, When isCurrentPinValid is called, Then it returns Failed with exception's localized message`() {
        coroutineRule.runTest {
            // Given
            whenever(pinStorageController.isPinValid(anyString()))
                .thenThrow(mockedExceptionWithMessage)

            // When
            interactor.isCurrentPinValid(
                pin = mockedPin
            ).runFlowTest {
                // Then
                assertEquals(
                    QuickPinInteractorPinValidPartialState.Failed(
                        errorMessage = mockedExceptionWithMessage.localizedMessage!!,
                        attemptsRemaining = 0
                    ),
                    awaitItem()
                )
            }
        }
    }

    // Case 4:
    // pinStorageController.isPinValid() throws an exception with no message.
    @Test
    fun `Given Case 4, When isCurrentPinValid is called, Then it returns Failed with the generic error message`() {
        coroutineRule.runTest {
            // Given
            whenever(pinStorageController.isPinValid(anyString()))
                .thenThrow(mockedExceptionWithNoMessage)

            // When
            interactor.isCurrentPinValid(
                pin = mockedPin
            ).runFlowTest {
                // Then
                assertEquals(
                    QuickPinInteractorPinValidPartialState.Failed(
                        errorMessage = mockedGenericErrorMessage,
                        attemptsRemaining = 0
                    ),
                    awaitItem()
                )
            }
        }
    }
    //endregion

    //region isPinMatched

    // Case 1:
    // resourceProvider.getString() throws no errors.
    // currentPin == newPin is true.
    @Test
    fun `Given Case 1, When isPinMatched is called, Then it returns Success`() {
        coroutineRule.runTest {
            // Given

            // When
            interactor.isPinMatched(
                currentPin = mockedPin,
                newPin = mockedPin
            ).runFlowTest {
                // Then
                assertEquals(
                    QuickPinInteractorPinValidPartialState.Success,
                    awaitItem()
                )
            }
        }
    }

    // Case 2:
    // resourceProvider.getString() throws no errors.
    // currentPin == newPin is false.
    @Test
    fun `Given Case 2, When isPinMatched is called, Then it returns Failed with the appropriate error message`() {
        coroutineRule.runTest {
            // Given
            whenever(resourceProvider.getString(R.string.quick_pin_invalid_error))
                .thenReturn(mockedInvalidPinMessage)

            // When
            interactor.isPinMatched(
                currentPin = mockedPin,
                newPin = mockedNewPin
            ).runFlowTest {
                // Then
                assertEquals(
                    QuickPinInteractorPinValidPartialState.Failed(
                        errorMessage = mockedInvalidPinMessage
                    ),
                    awaitItem()
                )

                verify(resourceProvider, times(1))
                    .getString(R.string.quick_pin_invalid_error)
            }
        }
    }

    // Case 3:
    // resourceProvider.getString() throws an exception with a message.
    @Test
    fun `Given Case 3, When isPinMatched is called, Then it returns Failed with exception's localized message`() {
        coroutineRule.runTest {
            // Given
            whenever(resourceProvider.getString(R.string.quick_pin_invalid_error))
                .thenThrow(mockedExceptionWithMessage)

            // When
            interactor.isPinMatched(
                currentPin = mockedPin,
                newPin = mockedNewPin
            ).runFlowTest {
                // Then
                assertEquals(
                    QuickPinInteractorPinValidPartialState.Failed(
                        errorMessage = mockedExceptionWithMessage.localizedMessage!!
                    ),
                    awaitItem()
                )
            }
        }
    }

    // Case 4:
    // resourceProvider.getString() throws an exception with no message.
    @Test
    fun `Given Case 4, When isPinMatched is called, Then it returns Failed with the generic error message`() {
        coroutineRule.runTest {
            // Given
            whenever(resourceProvider.getString(R.string.quick_pin_invalid_error))
                .thenThrow(mockedExceptionWithNoMessage)

            // When
            interactor.isPinMatched(
                currentPin = mockedPin,
                newPin = mockedNewPin
            ).runFlowTest {
                // Then
                assertEquals(
                    QuickPinInteractorPinValidPartialState.Failed(
                        errorMessage = mockedGenericErrorMessage
                    ),
                    awaitItem()
                )
            }
        }
    }
    //endregion

    //region Mocked objects needed for tests.
    private val mockedPin = "1234"
    private val mockedNewPin = "5678"
    private val mockedInitialPin = "0000"
    private val mockedPinsDontMatchMessage = "Pins do not match"
    private val mockedInvalidPinMessage = "Invalid quick pin"
    private val mockedEmptyPin = ""
    private val mockedBlankPin = "    "
    //endregion
}