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

package eu.europa.ec.authenticationlogic.controller.storage

import eu.europa.ec.authenticationlogic.config.StorageConfig
import eu.europa.ec.authenticationlogic.provider.PinStorageProvider
import junit.framework.TestCase.assertEquals
import junit.framework.TestCase.assertTrue
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.mockito.Mock
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

class TestPinStorageController {

    @Mock
    private lateinit var pinStorageProvider: PinStorageProvider

    @Mock
    private lateinit var storageConfig: StorageConfig

    private lateinit var controller: PinStorageControllerImpl
    private lateinit var closeable: AutoCloseable

    @Before
    fun before() {
        closeable = MockitoAnnotations.openMocks(this)

        whenever(storageConfig.pinStorageProvider).thenReturn(pinStorageProvider)
        controller = PinStorageControllerImpl(storageConfig)
    }

    @After
    fun after() {
        closeable.close()
    }

    //region hasPin

    // Case 1:
    // pinStorageProvider.hasPin() returns false.
    @Test
    fun `Given Case 1, When hasPin is called, Then it returns false`() {
        // Given
        whenever(pinStorageProvider.hasPin()).thenReturn(false)

        // When
        val result = controller.hasPin()

        // Then
        assertEquals(false, result)
        verify(pinStorageProvider, times(1)).hasPin()
    }

    // Case 2:
    // pinStorageProvider.hasPin() returns true.
    @Test
    fun `Given Case 2, When hasPin is called, Then it returns true`() {
        // Given
        whenever(pinStorageProvider.hasPin()).thenReturn(true)

        // When
        val result = controller.hasPin()

        // Then
        assertEquals(true, result)
    }
    //endregion

    //region isPinValid — lockout guard

    // Case 1:
    // Device is currently locked out.
    @Test
    fun `Given Case 1, When isPinValid is called while locked out, Then it returns LockedOut`() {
        // Given
        whenever(pinStorageProvider.isCurrentlyLockedOut()).thenReturn(true)
        whenever(pinStorageProvider.getLockoutUntil()).thenReturn(1_060_000L)
        whenever(pinStorageProvider.getFailedAttempts()).thenReturn(4)

        // When
        val result = controller.isPinValid(mockedPin)

        // Then
        assertTrue(result is PinValidationResult.LockedOut)
        val lockedOut = result as PinValidationResult.LockedOut
        assertEquals(1_060_000L, lockedOut.lockoutEndTimeMillis)
        assertEquals(4, lockedOut.attemptsUsed)
    }
    //endregion

    //region isPinValid — correct PIN

    // Case 2:
    // PIN is valid; failed attempts are reset.
    @Test
    fun `Given Case 2, When isPinValid is called with the correct pin, Then it returns Success and resets attempts`() {
        // Given
        whenever(pinStorageProvider.isCurrentlyLockedOut()).thenReturn(false)
        whenever(pinStorageProvider.isPinValid(mockedPin)).thenReturn(true)

        // When
        val result = controller.isPinValid(mockedPin)

        // Then
        assertEquals(PinValidationResult.Success, result)
        verify(pinStorageProvider, times(1)).resetFailedAttempts()
    }
    //endregion

    //region isPinValid — wrong PIN, no lockout yet

    // Case 3:
    // Wrong PIN, attempts below threshold — returns Failed with remaining count.
    @Test
    fun `Given Case 3, When isPinValid is called with wrong pin below threshold, Then it returns Failed with attempts remaining`() {
        // Given
        whenever(pinStorageProvider.isCurrentlyLockedOut()).thenReturn(false)
        whenever(pinStorageProvider.isPinValid(mockedPin)).thenReturn(false)
        whenever(pinStorageProvider.incrementFailedAttempts()).thenReturn(2)

        // When
        val result = controller.isPinValid(mockedPin)

        // Then
        assertTrue(result is PinValidationResult.Failed)
        val failed = result as PinValidationResult.Failed
        assertEquals(2, failed.attemptsRemaining) // MAX_ATTEMPTS(4) - 2
    }
    //endregion

    //region isPinValid — lockout triggered

    // Case 4:
    // Wrong PIN, attempts reach MAX_ATTEMPTS(4) — first lockout of 1 minute duration.
    @Test
    fun `Given Case 4, When isPinValid reaches MAX_ATTEMPTS, Then it requests a 1-minute lockout`() {
        // Given
        whenever(pinStorageProvider.isCurrentlyLockedOut()).thenReturn(false)
        whenever(pinStorageProvider.isPinValid(mockedPin)).thenReturn(false)
        whenever(pinStorageProvider.incrementFailedAttempts()).thenReturn(4)
        whenever(pinStorageProvider.getLockoutUntil()).thenReturn(1_060_000L)

        // When
        val result = controller.isPinValid(mockedPin)

        // Then
        assertTrue(result is PinValidationResult.LockedOut)
        val lockedOut = result as PinValidationResult.LockedOut
        assertEquals(1_060_000L, lockedOut.lockoutEndTimeMillis)
        verify(pinStorageProvider, times(1)).setLockoutForDuration(60_000L)
    }

    // Case 5:
    // 5th attempt — lockout duration escalates to 5 minutes.
    @Test
    fun `Given Case 5, When isPinValid reaches 5 attempts, Then lockout duration is 5 minutes`() {
        // Given
        whenever(pinStorageProvider.isCurrentlyLockedOut()).thenReturn(false)
        whenever(pinStorageProvider.isPinValid(mockedPin)).thenReturn(false)
        whenever(pinStorageProvider.incrementFailedAttempts()).thenReturn(5)

        // When
        controller.isPinValid(mockedPin)

        // Then
        val captor = argumentCaptor<Long>()
        verify(pinStorageProvider).setLockoutForDuration(captor.capture())
        assertEquals(5 * 60_000L, captor.firstValue)
    }

    // Case 6:
    // 10th+ attempt — lockout caps at 8 hours.
    @Test
    fun `Given Case 6, When isPinValid exceeds 9 attempts, Then lockout duration is 8 hours`() {
        // Given
        whenever(pinStorageProvider.isCurrentlyLockedOut()).thenReturn(false)
        whenever(pinStorageProvider.isPinValid(any())).thenReturn(false)
        whenever(pinStorageProvider.incrementFailedAttempts()).thenReturn(10)

        // When
        controller.isPinValid(mockedPin)

        // Then
        val captor = argumentCaptor<Long>()
        verify(pinStorageProvider).setLockoutForDuration(captor.capture())
        assertEquals(480 * 60_000L, captor.firstValue)
    }
    //endregion

    //region Mocked objects
    private val mockedPin = "1234"
    //endregion
}
