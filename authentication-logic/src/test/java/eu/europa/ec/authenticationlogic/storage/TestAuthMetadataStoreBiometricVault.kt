/*
 * Copyright (c) 2026 European Commission
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

import junit.framework.TestCase.assertEquals
import junit.framework.TestCase.assertFalse
import junit.framework.TestCase.assertNotNull
import junit.framework.TestCase.assertNull
import junit.framework.TestCase.assertTrue
import org.junit.Test

class TestAuthMetadataStoreBiometricVault {

    private val fakeIv = ByteArray(12) { (it + 5).toByte() }
    private val fakeCiphertext = ByteArray(48) { (it + 50).toByte() }

    private fun buildMeta(
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
        bootId = "boot-test",
        failedAttempts = 0,
        lockoutDeadline = 0L,
        lockoutDuration = 0L,
        biometricEnabled = biometricEnabled,
        biometricWrappedVaultIv = biometricWrappedVaultIv,
        biometricWrappedVault = biometricWrappedVault,
        writeCounter = 1L,
    )

    @Test
    fun `Given Case, When BiometricKeyInvalidatedException is constructed with message, Then message is preserved`() {
        val msg = "custom error"
        val ex = BiometricKeyInvalidatedException(msg)
        assertEquals(msg, ex.message)
    }

    @Test
    fun `Given Case, When AuthMetadata is copied with biometric fields, Then fields are preserved`() {
        val meta = buildMeta(
            biometricEnabled = true,
            biometricWrappedVaultIv = fakeIv,
            biometricWrappedVault = fakeCiphertext,
        )
        assertTrue(meta.biometricEnabled)
        assertTrue(meta.biometricWrappedVaultIv!!.contentEquals(fakeIv))
        assertTrue(meta.biometricWrappedVault!!.contentEquals(fakeCiphertext))
    }

    @Test
    fun `Given Case, When AuthMetadata is copied without biometric fields, Then fields are null`() {
        val meta = buildMeta(
            biometricEnabled = true,
            biometricWrappedVaultIv = fakeIv,
            biometricWrappedVault = fakeCiphertext,
        )
        val cleared = meta.copy(
            biometricEnabled = false,
            biometricWrappedVaultIv = null,
            biometricWrappedVault = null,
        )
        assertFalse(cleared.biometricEnabled)
        assertNull(cleared.biometricWrappedVaultIv)
        assertNull(cleared.biometricWrappedVault)
    }

    @Test
    fun `Given Case, When encode then decode with biometric data, Then biometric fields are preserved`() {
        val meta = buildMeta(
            biometricEnabled = true,
            biometricWrappedVaultIv = fakeIv,
            biometricWrappedVault = fakeCiphertext,
        )
        val encoded = AuthMetadataCodec.encode(meta)
        val decoded = AuthMetadataCodec.decode(encoded)
        assertTrue(decoded.biometricEnabled)
        assertTrue(decoded.biometricWrappedVaultIv!!.contentEquals(fakeIv))
        assertTrue(decoded.biometricWrappedVault!!.contentEquals(fakeCiphertext))
    }

    @Test
    fun `Given Case, When encode then decode without biometric data, Then biometric fields are null`() {
        val meta = buildMeta(biometricEnabled = false)
        val encoded = AuthMetadataCodec.encode(meta)
        val decoded = AuthMetadataCodec.decode(encoded)
        assertFalse(decoded.biometricEnabled)
        assertNull(decoded.biometricWrappedVaultIv)
        assertNull(decoded.biometricWrappedVault)
    }

    @Test
    fun `Given Case, When biometricEnabled true but no vault data, Then codec treats as disabled`() {
        val meta = buildMeta(
            biometricEnabled = true,
            biometricWrappedVaultIv = null,
            biometricWrappedVault = null,
        )
        val encoded = AuthMetadataCodec.encode(meta)
        val decoded = AuthMetadataCodec.decode(encoded)
        assertFalse(decoded.biometricEnabled)
        assertNull(decoded.biometricWrappedVaultIv)
        assertNull(decoded.biometricWrappedVault)
    }

    @Test
    fun `Given Case, When metadata is updated for key invalidation, Then biometric fields are cleared`() {
        val meta = buildMeta(
            biometricEnabled = true,
            biometricWrappedVaultIv = fakeIv,
            biometricWrappedVault = fakeCiphertext,
        )
        val invalidated = meta.copy(
            biometricEnabled = false,
            biometricWrappedVaultIv = null,
            biometricWrappedVault = null,
        )
        val encoded = AuthMetadataCodec.encode(invalidated)
        val decoded = AuthMetadataCodec.decode(encoded)
        assertFalse(decoded.biometricEnabled)
        assertNull(decoded.biometricWrappedVaultIv)
        assertNull(decoded.biometricWrappedVault)
    }

    @Test
    fun `Given Case, When biometric vault IV is wrong size, Then codec throws`() {
        val meta = buildMeta(
            biometricEnabled = true,
            biometricWrappedVaultIv = ByteArray(10),
            biometricWrappedVault = fakeCiphertext,
        )
        var threw = false
        try {
            AuthMetadataCodec.encode(meta)
        } catch (_: IllegalArgumentException) {
            threw = true
        }
        assertTrue(threw)
    }

    @Test
    fun `Given Case0, When enrolment is committed, Then biometricEnabled is true and fields are non-null`() {
        val before = buildMeta(biometricEnabled = false)
        val after = before.copy(
            biometricEnabled = true,
            biometricWrappedVaultIv = fakeIv,
            biometricWrappedVault = fakeCiphertext,
        )
        assertFalse(before.biometricEnabled)
        assertTrue(after.biometricEnabled)
        assertNull(before.biometricWrappedVaultIv)
        assertNotNull(after.biometricWrappedVaultIv)
    }

    @Test
    fun `Given Case, When re-enrolling after invalidation, Then new IV and ciphertext replace old values`() {
        val invalidated = buildMeta(
            biometricEnabled = false,
            biometricWrappedVaultIv = null,
            biometricWrappedVault = null,
        )
        val reenrolled = invalidated.copy(
            biometricEnabled = true,
            biometricWrappedVaultIv = fakeIv,
            biometricWrappedVault = fakeCiphertext,
        )
        assertFalse(invalidated.biometricEnabled)
        assertNull(invalidated.biometricWrappedVaultIv)
        assertTrue(reenrolled.biometricEnabled)
        assertTrue(reenrolled.biometricWrappedVaultIv!!.contentEquals(fakeIv))
        assertTrue(reenrolled.biometricWrappedVault!!.contentEquals(fakeCiphertext))
    }

    @Test
    fun `Given Case, When biometricEnabled is false, Then biometricWrappedVaultIv is null`() {
        val meta = buildMeta(biometricEnabled = false)
        assertNull(meta.biometricWrappedVaultIv)
        assertNull(meta.biometricWrappedVault)
    }

    @Test
    fun `Given Case, When biometricEnabled is true, Then IV and ciphertext are available for unlock`() {
        val meta = buildMeta(
            biometricEnabled = true,
            biometricWrappedVaultIv = fakeIv,
            biometricWrappedVault = fakeCiphertext,
        )
        assertNotNull(meta.biometricWrappedVaultIv)
        assertNotNull(meta.biometricWrappedVault)
        assertEquals(12, meta.biometricWrappedVaultIv!!.size)
    }
}
