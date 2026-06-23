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

import junit.framework.TestCase.assertEquals
import junit.framework.TestCase.assertFalse
import junit.framework.TestCase.assertNull
import junit.framework.TestCase.assertTrue
import org.junit.Test

class TestAuthMetadataCodec {

    private fun buildMeta(biometricEnabled: Boolean = false) = AuthMetadata(
        version = 0x01,
        kdfAlgo = 0x01,
        kdfM = 65_536,
        kdfT = 3,
        kdfP = 1,
        pinSalt = ByteArray(32) { it.toByte() },
        wrappedVaultIv = ByteArray(12) { (it + 10).toByte() },
        wrappedVault = ByteArray(48) { (it + 20).toByte() },
        bootId = "boot-test-A",
        failedAttempts = 2,
        lockoutDeadline = 123_456L,
        lockoutDuration = 60_000L,
        biometricEnabled = biometricEnabled,
        biometricWrappedVaultIv = if (biometricEnabled) ByteArray(12) { (it + 5).toByte() } else null,
        biometricWrappedVault = if (biometricEnabled) ByteArray(48) { (it + 50).toByte() } else null,
        writeCounter = 7L,
    )

    // Case 1: round-trip encode/decode without biometrics preserves all fields.
    @Test
    fun `Given Case 1, When encode then decode without biometrics, Then all fields are preserved`() {
        val original = buildMeta(biometricEnabled = false)
        val decoded = AuthMetadataCodec.decode(AuthMetadataCodec.encode(original))

        assertEquals(original.version, decoded.version)
        assertEquals(original.kdfM, decoded.kdfM)
        assertEquals(original.kdfT, decoded.kdfT)
        assertEquals(original.kdfP, decoded.kdfP)
        assertTrue(original.pinSalt.contentEquals(decoded.pinSalt))
        assertTrue(original.wrappedVaultIv.contentEquals(decoded.wrappedVaultIv))
        assertTrue(original.wrappedVault.contentEquals(decoded.wrappedVault))
        assertEquals(original.failedAttempts, decoded.failedAttempts)
        assertEquals(original.lockoutDeadline, decoded.lockoutDeadline)
        assertEquals(original.lockoutDuration, decoded.lockoutDuration)
        assertEquals(original.bootId, decoded.bootId)
        assertFalse(decoded.biometricEnabled)
        assertNull(decoded.biometricWrappedVaultIv)
        assertNull(decoded.biometricWrappedVault)
        assertEquals(original.writeCounter, decoded.writeCounter)
    }

    // Case 2: round-trip encode/decode with biometrics preserves biometric fields.
    @Test
    fun `Given Case 2, When encode then decode with biometrics, Then biometric fields are preserved`() {
        val original = buildMeta(biometricEnabled = true)
        val decoded = AuthMetadataCodec.decode(AuthMetadataCodec.encode(original))

        assertTrue(decoded.biometricEnabled)
        assertTrue(original.biometricWrappedVaultIv!!.contentEquals(decoded.biometricWrappedVaultIv!!))
        assertTrue(original.biometricWrappedVault!!.contentEquals(decoded.biometricWrappedVault!!))
    }

    // Case 3: a truncated blob (too short to parse) throws AuthMetadataCorruptException.
    @Test
    fun `Given Case 3, When blob is truncated, Then decode throws AuthMetadataCorruptException`() {
        val encoded = AuthMetadataCodec.encode(buildMeta())
        val truncated = encoded.copyOf(10)

        var threw = false
        try {
            AuthMetadataCodec.decode(truncated)
        } catch (_: AuthMetadataCorruptException) {
            threw = true
        }
        assertTrue(threw)
    }

    // Case 4: unknown version byte throws AuthMetadataCorruptException.
    @Test
    fun `Given Case 4, When version byte is unknown, Then decode throws AuthMetadataCorruptException`() {
        val encoded = AuthMetadataCodec.encode(buildMeta())
        encoded[0] = 0xFF.toByte()

        var threw = false
        try {
            AuthMetadataCodec.decode(encoded)
        } catch (_: AuthMetadataCorruptException) {
            threw = true
        }
        assertTrue(threw)
    }

    // Case 5: writeCounter round-trips correctly.
    @Test
    fun `Given Case 5, When writeCounter is set, Then it round-trips correctly`() {
        val meta = buildMeta().copy(writeCounter = Long.MAX_VALUE)
        val decoded = AuthMetadataCodec.decode(AuthMetadataCodec.encode(meta))
        assertEquals(Long.MAX_VALUE, decoded.writeCounter)
    }
}
