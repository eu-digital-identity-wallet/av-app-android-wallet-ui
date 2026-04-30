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

package eu.europa.ec.authenticationlogic.storage

import eu.europa.ec.businesslogic.controller.storage.PrefsController
import eu.europa.ec.businesslogic.provider.BootIdProvider
import eu.europa.ec.businesslogic.provider.ElapsedRealtimeClock
import junit.framework.TestCase.assertEquals
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.mockito.Mock
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

class TestPrefsPinStorageProvider {

    @Mock
    private lateinit var prefsController: PrefsController

    private lateinit var clock: ElapsedRealtimeClock
    private lateinit var bootIdProvider: BootIdProvider
    private lateinit var provider: PrefsPinStorageProvider
    private lateinit var closeable: AutoCloseable

    private var fakeNow: Long = 10_000L
    private var fakeBootId: String = "boot-A"

    @Before
    fun before() {
        closeable = MockitoAnnotations.openMocks(this)
        clock = ElapsedRealtimeClock { fakeNow }
        bootIdProvider = BootIdProvider { fakeBootId }
        provider = PrefsPinStorageProvider(prefsController, clock, bootIdProvider)
    }

    @After
    fun after() {
        closeable.close()
    }

    //region isCurrentlyLockedOut

    // Case 1:
    // lockoutUntil == 0 — no lockout stored.
    @Test
    fun `Given Case 1, When isCurrentlyLockedOut is called with no lockout, Then it returns false`() {
        // Given
        whenever(prefsController.getLong("PinLockoutUntil", 0L)).thenReturn(0L)

        // When
        val result = provider.isCurrentlyLockedOut()

        // Then
        assertEquals(false, result)
    }

    // Case 2:
    // lockoutUntil is in the future and boot id matches — user is locked out.
    @Test
    fun `Given Case 2, When isCurrentlyLockedOut is called and lockout deadline is in the future, Then it returns true`() {
        // Given
        val lockoutUntil = fakeNow + 30_000L
        whenever(prefsController.getLong("PinLockoutUntil", 0L)).thenReturn(lockoutUntil)
        whenever(prefsController.getString("PinLockoutBootId", "")).thenReturn(fakeBootId)

        // When
        val result = provider.isCurrentlyLockedOut()

        // Then
        assertEquals(true, result)
    }

    // Case 3:
    // lockoutUntil is in the past (same boot) — lockout has expired.
    @Test
    fun `Given Case 3, When isCurrentlyLockedOut is called and lockout deadline has passed, Then it returns false`() {
        // Given
        val lockoutUntil = fakeNow - 1L
        whenever(prefsController.getLong("PinLockoutUntil", 0L)).thenReturn(lockoutUntil)
        whenever(prefsController.getString("PinLockoutBootId", "")).thenReturn(fakeBootId)

        // When
        val result = provider.isCurrentlyLockedOut()

        // Then
        assertEquals(false, result)
    }

    // Case 4:
    // lockoutUntil equals fakeNow exactly (same boot) — boundary, not locked out.
    @Test
    fun `Given Case 4, When isCurrentlyLockedOut is called at the exact lockout boundary, Then it returns false`() {
        // Given
        whenever(prefsController.getLong("PinLockoutUntil", 0L)).thenReturn(fakeNow)
        whenever(prefsController.getString("PinLockoutBootId", "")).thenReturn(fakeBootId)

        // When
        val result = provider.isCurrentlyLockedOut()

        // Then
        assertEquals(false, result)
    }
    //endregion

    //region reboot re-anchoring

    // Case 5:
    // After reboot, the stored deadline is re-anchored to now + duration so the attacker
    // cannot shorten the lockout by rebooting.
    @Test
    fun `Given Case 5, When boot id changes, Then the lockout is re-anchored to now plus duration`() {
        // Given — original lockout was set at t=0 under boot-A, duration 60s
        val originalDeadline = 60_000L
        whenever(prefsController.getLong("PinLockoutUntil", 0L)).thenReturn(originalDeadline)
        whenever(prefsController.getLong("PinLockoutDurationMs", 0L)).thenReturn(60_000L)
        whenever(prefsController.getString("PinLockoutBootId", "")).thenReturn("boot-A")

        // Simulate reboot: boot id is now boot-B and elapsedRealtime restarted
        fakeBootId = "boot-B"
        fakeNow = 5_000L

        // When
        val result = provider.getLockoutUntil()

        // Then — deadline re-anchored to now + duration, and boot id updated
        val expected = fakeNow + 60_000L
        assertEquals(expected, result)
        verify(prefsController, times(1)).setLong("PinLockoutUntil", expected)
        verify(prefsController, times(1)).setString("PinLockoutBootId", "boot-B")
    }

    // Case 6:
    // A legacy entry without duration metadata — clear it rather than keep user locked forever.
    @Test
    fun `Given Case 6, When boot id changes and no duration metadata exists, Then the lockout is cleared`() {
        // Given
        whenever(prefsController.getLong("PinLockoutUntil", 0L)).thenReturn(60_000L)
        whenever(prefsController.getLong("PinLockoutDurationMs", 0L)).thenReturn(0L)
        whenever(prefsController.getString("PinLockoutBootId", "")).thenReturn("boot-A")

        fakeBootId = "boot-B"

        // When
        val result = provider.getLockoutUntil()

        // Then
        assertEquals(0L, result)
        verify(prefsController, times(1)).setLong("PinLockoutUntil", 0L)
    }
    //endregion

    //region setLockoutForDuration

    // Case 7:
    // Setting a lockout persists deadline = now + duration, the duration, and the boot id.
    @Test
    fun `Given Case 7, When setLockoutForDuration is called, Then deadline, duration and boot id are persisted`() {
        // Given
        fakeNow = 42_000L
        fakeBootId = "boot-X"

        // When
        provider.setLockoutForDuration(60_000L)

        // Then
        verify(prefsController, times(1)).setLong("PinLockoutUntil", 102_000L)
        verify(prefsController, times(1)).setLong("PinLockoutDurationMs", 60_000L)
        verify(prefsController, times(1)).setString("PinLockoutBootId", "boot-X")
    }
    //endregion

    //region resetFailedAttempts

    // Case 8:
    // Reset clears attempts, deadline, duration and boot id.
    @Test
    fun `Given Case 8, When resetFailedAttempts is called, Then all lockout state is cleared`() {
        // When
        provider.resetFailedAttempts()

        // Then
        verify(prefsController, times(1)).setInt("PinFailedAttempts", 0)
        verify(prefsController, times(1)).setLong("PinLockoutUntil", 0L)
        verify(prefsController, times(1)).setLong("PinLockoutDurationMs", 0L)
        verify(prefsController, times(1)).setString("PinLockoutBootId", "")
    }
    //endregion

    //region incrementFailedAttempts

    // Case 9:
    // incrementFailedAttempts increments and persists.
    @Test
    fun `Given Case 9, When incrementFailedAttempts is called, Then the count is incremented and persisted`() {
        // Given
        whenever(prefsController.getInt("PinFailedAttempts", 0)).thenReturn(2)

        // When
        val result = provider.incrementFailedAttempts()

        // Then
        assertEquals(3, result)
        verify(prefsController, times(1)).setInt("PinFailedAttempts", 3)
    }
    //endregion
}
