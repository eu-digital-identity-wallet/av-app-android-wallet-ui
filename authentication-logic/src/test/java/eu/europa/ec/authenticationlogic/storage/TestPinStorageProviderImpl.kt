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

import eu.europa.ec.authenticationlogic.provider.VaultKeyProvider
import eu.europa.ec.businesslogic.provider.BootIdProvider
import eu.europa.ec.businesslogic.provider.ElapsedRealtimeClock
import junit.framework.TestCase.assertEquals
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.mockito.Mock
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

class TestPinStorageProviderImpl {

    @Mock
    private lateinit var authMetadataStore: AuthMetadataStore

    @Mock
    private lateinit var vaultKeyProvider: VaultKeyProvider

    private lateinit var clock: ElapsedRealtimeClock
    private lateinit var bootIdProvider: BootIdProvider
    private lateinit var provider: PinStorageProviderImpl
    private lateinit var closeable: AutoCloseable

    private var fakeNow: Long = 10_000L
    private var fakeBootId: String = "boot-A"

    @Before
    fun before() {
        closeable = MockitoAnnotations.openMocks(this)
        clock = ElapsedRealtimeClock { fakeNow }
        bootIdProvider = BootIdProvider { fakeBootId }
        provider = PinStorageProviderImpl(authMetadataStore, clock, bootIdProvider, vaultKeyProvider)
    }

    @After
    fun after() {
        closeable.close()
    }

    private fun buildMeta(
        failedAttempts: Int = 0,
        lockoutDeadline: Long = 0L,
        lockoutDuration: Long = 0L,
        bootId: String = fakeBootId,
        writeCounter: Long = 1L,
        biometricEnabled: Boolean = false,
        biometricWrappedVaultIv: ByteArray? = null,
        biometricWrappedVault: ByteArray? = null,
    ) = AuthMetadata(
        version = 0x01,
        kdfAlgo = 0x01,
        kdfM = 65_536,
        kdfT = 3,
        kdfP = 1,
        pinSalt = ByteArray(32),
        wrappedVaultIv = ByteArray(12),
        wrappedVault = ByteArray(48),
        bootId = bootId,
        failedAttempts = failedAttempts,
        lockoutDeadline = lockoutDeadline,
        lockoutDuration = lockoutDuration,
        writeCounter = writeCounter,
        biometricEnabled = biometricEnabled,
        biometricWrappedVaultIv = biometricWrappedVaultIv,
        biometricWrappedVault = biometricWrappedVault,
    )

    //region isCurrentlyLockedOut

    // Case 1: no lockout stored — not locked out.
    @Test
    fun `Given Case 1, When isCurrentlyLockedOut with no lockout, Then it returns false`() {
        runBlocking {
            whenever(authMetadataStore.read()).thenReturn(buildMeta(lockoutDeadline = 0L))
        }
        assertEquals(false, provider.isCurrentlyLockedOut())
    }

    // Case 2: lockout deadline in the future (same boot) — locked out.
    @Test
    fun `Given Case 2, When lockout deadline is in the future, Then it returns true`() {
        val deadline = fakeNow + 30_000L
        runBlocking {
            whenever(authMetadataStore.read()).thenReturn(buildMeta(lockoutDeadline = deadline))
        }
        assertEquals(true, provider.isCurrentlyLockedOut())
    }

    // Case 3: lockout deadline in the past (same boot) — not locked out.
    @Test
    fun `Given Case 3, When lockout deadline has passed, Then it returns false`() {
        runBlocking {
            whenever(authMetadataStore.read())
                .thenReturn(buildMeta(lockoutDeadline = fakeNow - 1L))
        }
        assertEquals(false, provider.isCurrentlyLockedOut())
    }

    // Case 4: lockout deadline equals fakeNow — boundary, not locked out.
    @Test
    fun `Given Case 4, When at exact lockout boundary, Then it returns false`() {
        runBlocking {
            whenever(authMetadataStore.read())
                .thenReturn(buildMeta(lockoutDeadline = fakeNow))
        }
        assertEquals(false, provider.isCurrentlyLockedOut())
    }
    //endregion

    //region reboot re-anchoring

    // Case 5: after reboot with active lockout, deadline is re-anchored.
    @Test
    fun `Given Case 5, When boot id changes with active lockout, Then the lockout is re-anchored`() = runBlocking {
        val originalDeadline = 60_000L
        val duration = 60_000L
        whenever(authMetadataStore.read())
            .thenReturn(buildMeta(lockoutDeadline = originalDeadline, lockoutDuration = duration, bootId = "boot-A"))

        fakeBootId = "boot-B"
        fakeNow = 5_000L

        val result = provider.getLockoutUntil()

        val expected = fakeNow + duration
        assertEquals(expected, result)
        val captor = argumentCaptor<AuthMetadata>()
        verify(authMetadataStore, times(1)).write(captor.capture())
        assertEquals(expected, captor.firstValue.lockoutDeadline)
        assertEquals("boot-B", captor.firstValue.bootId)
    }
    //endregion

    //region setLockoutForDuration

    // Case 6: setting a lockout persists deadline = now + duration.
    @Test
    fun `Given Case 6, When setLockoutForDuration is called, Then deadline and duration are written`() = runBlocking {
        fakeNow = 42_000L
        whenever(authMetadataStore.read())
            .thenReturn(buildMeta())

        provider.setLockoutForDuration(60_000L)

        val captor = argumentCaptor<AuthMetadata>()
        verify(authMetadataStore, times(1)).write(captor.capture())
        assertEquals(102_000L, captor.firstValue.lockoutDeadline)
        assertEquals(60_000L, captor.firstValue.lockoutDuration)
    }
    //endregion

    //region resetFailedAttempts

    // Case 7: reset clears attempts and lockout.
    @Test
    fun `Given Case 7, When resetFailedAttempts is called, Then all lockout state is cleared`() = runBlocking {
        whenever(authMetadataStore.read())
            .thenReturn(buildMeta(failedAttempts = 3, lockoutDeadline = 1000L, lockoutDuration = 60_000L))

        provider.resetFailedAttempts()

        val captor = argumentCaptor<AuthMetadata>()
        verify(authMetadataStore, times(1)).write(captor.capture())
        assertEquals(0, captor.firstValue.failedAttempts)
        assertEquals(0L, captor.firstValue.lockoutDeadline)
        assertEquals(0L, captor.firstValue.lockoutDuration)
    }
    //endregion

    //region incrementFailedAttempts

    // Case 8: incrementFailedAttempts increments and writes.
    @Test
    fun `Given Case 8, When incrementFailedAttempts is called, Then count is incremented and written`() = runBlocking {
        whenever(authMetadataStore.read()).thenReturn(buildMeta(failedAttempts = 2))

        val result = provider.incrementFailedAttempts()

        assertEquals(3, result)
        val captor = argumentCaptor<AuthMetadata>()
        verify(authMetadataStore, times(1)).write(captor.capture())
        assertEquals(3, captor.firstValue.failedAttempts)
    }
    //endregion

    //region hasPin

    // Case 9: null blob means no PIN enrolled.
    @Test
    fun `Given Case 9, When blob is null, Then hasPin returns false`() {
        runBlocking { whenever(authMetadataStore.read()).thenReturn(null) }
        assertEquals(false, provider.hasPin())
    }

    // Case 10: non-null blob means PIN enrolled.
    @Test
    fun `Given Case 10, When blob is present, Then hasPin returns true`() {
        runBlocking { whenever(authMetadataStore.read()).thenReturn(buildMeta()) }
        assertEquals(true, provider.hasPin())
    }
    //endregion

    //region rollback protection

    // Case 11: null returned from store (e.g. rollback detected) means no lockout.
    @Test
    fun `Given Case 11, When store returns null after rollback, Then isCurrentlyLockedOut returns false`() {
        runBlocking { whenever(authMetadataStore.read()).thenReturn(null) }
        assertEquals(false, provider.isCurrentlyLockedOut())
    }
    //endregion

    //region setPin

    // Case 12: setPin with no existing metadata creates fresh AuthMetadata with defaults.
    @Test
    fun `Given Case 12, When setPin with no existing metadata, Then fresh AuthMetadata is created with biometric defaults`() = runBlocking {
        whenever(authMetadataStore.read()).thenReturn(null)

        provider.setPin("123456")

        val captor = argumentCaptor<AuthMetadata>()
        verify(authMetadataStore, times(1)).write(captor.capture())
        val written = captor.firstValue
        assertEquals(false, written.biometricEnabled)
        assertEquals(null, written.biometricWrappedVaultIv)
        assertEquals(null, written.biometricWrappedVault)
        assertEquals(0L, written.writeCounter)
        assertEquals(0, written.failedAttempts)
        assertEquals(0L, written.lockoutDeadline)
        assertEquals(0L, written.lockoutDuration)
        assertEquals(fakeBootId, written.bootId)
    }

    // Case 13: setPin with existing metadata preserves biometric fields.
    @Test
    fun `Given Case 13, When setPin with existing biometric metadata, Then biometric fields are preserved`() = runBlocking {
        val bioIv = ByteArray(12) { it.toByte() }
        val bioVault = ByteArray(48) { (it + 1).toByte() }
        whenever(vaultKeyProvider.isUnlocked()).thenReturn(true)
        whenever(vaultKeyProvider.getVaultKey()).thenReturn(ByteArray(32))
        whenever(authMetadataStore.read()).thenReturn(
            buildMeta(
                biometricEnabled = true,
                biometricWrappedVaultIv = bioIv,
                biometricWrappedVault = bioVault,
                writeCounter = 5L,
            )
        )

        provider.setPin("654321")

        val captor = argumentCaptor<AuthMetadata>()
        verify(authMetadataStore, times(1)).write(captor.capture())
        val written = captor.firstValue
        assertEquals(true, written.biometricEnabled)
        assertEquals(true, written.biometricWrappedVaultIv?.contentEquals(bioIv))
        assertEquals(true, written.biometricWrappedVault?.contentEquals(bioVault))
        assertEquals(5L, written.writeCounter)
    }

    // Case 14: setPin with existing metadata resets failedAttempts and lockout.
    @Test
    fun `Given Case 14, When setPin with existing lockout state, Then failedAttempts and lockout are reset`() = runBlocking {
        whenever(vaultKeyProvider.isUnlocked()).thenReturn(true)
        whenever(vaultKeyProvider.getVaultKey()).thenReturn(ByteArray(32))
        whenever(authMetadataStore.read()).thenReturn(
            buildMeta(
                failedAttempts = 4,
                lockoutDeadline = 99_000L,
                lockoutDuration = 60_000L,
            )
        )

        provider.setPin("111111")

        val captor = argumentCaptor<AuthMetadata>()
        verify(authMetadataStore, times(1)).write(captor.capture())
        val written = captor.firstValue
        assertEquals(0, written.failedAttempts)
        assertEquals(0L, written.lockoutDeadline)
        assertEquals(0L, written.lockoutDuration)
    }

    // Case 15: setPin with existing metadata reuses vault key when vault is unlocked.
    @Test
    fun `Given Case 15, When setPin with unlocked vault, Then vault key is reused`() {
        runBlocking {
            whenever(vaultKeyProvider.isUnlocked()).thenReturn(true)
            whenever(vaultKeyProvider.getVaultKey()).thenReturn(ByteArray(32))
            whenever(authMetadataStore.read()).thenReturn(buildMeta())

            provider.setPin("999999")

            verify(vaultKeyProvider).isUnlocked()
            verify(vaultKeyProvider).getVaultKey()
        }
    }
    //endregion
}
