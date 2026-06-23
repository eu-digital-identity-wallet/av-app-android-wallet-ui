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
 * ANY KIND, express or implied. See the Licence for the specific language
 * governing permissions and limitations under the Licence.
 */

package eu.europa.ec.authenticationlogic.provider

import junit.framework.TestCase.assertEquals
import junit.framework.TestCase.assertFalse
import junit.framework.TestCase.assertNull
import junit.framework.TestCase.assertTrue
import org.junit.After
import org.junit.Before
import org.junit.Test

class TestVaultKeyProviderImpl {

    private lateinit var provider: VaultKeyProviderImpl

    @Before
    fun before() {
        provider = VaultKeyProviderImpl()
    }

    @After
    fun after() {
        provider.lock()
    }

    // Case 1: deriveSubKey throws when vault key is not unlocked.
    @Test(expected = IllegalStateException::class)
    fun `Given Case 1, When deriveSubKey without unlock, Then throws IllegalStateException`() {
        provider.deriveSubKey("room_passphrase_v1")
    }

    // Case 2: deriveSubKey returns 32 bytes after unlock.
    @Test
    fun `Given Case 2, When deriveSubKey after unlock, Then returns 32 bytes`() {
        val key = ByteArray(32) { it.toByte() }
        provider.unlock(key)
        val derived = provider.deriveSubKey("room_passphrase_v1")
        assertEquals(32, derived.size)
    }

    // Case 3: deriveSubKey is deterministic (same key + label = same output).
    @Test
    fun `Given Case 3, When deriveSubKey with same key and label, Then output is identical`() {
        val key = ByteArray(32) { (it + 42).toByte() }
        provider.unlock(key)
        val first = provider.deriveSubKey("room_passphrase_v1")
        val second = provider.deriveSubKey("room_passphrase_v1")
        assertTrue(first.contentEquals(second))
    }

    // Case 4: deriveSubKey with different labels produces different keys.
    @Test
    fun `Given Case 4, When deriveSubKey with different labels, Then outputs differ`() {
        val key = ByteArray(32) { it.toByte() }
        provider.unlock(key)
        val a = provider.deriveSubKey("room_passphrase_v1")
        val b = provider.deriveSubKey("other_label")
        assertFalse(a.contentEquals(b))
    }

    // Case 5: deriveSubKey with different vault keys produces different outputs.
    @Test
    fun `Given Case 5, When deriveSubKey with different vault keys, Then outputs differ`() {
        val key1 = ByteArray(32) { it.toByte() }
        provider.unlock(key1)
        val derived1 = provider.deriveSubKey("room_passphrase_v1")

        provider.lock()
        val key2 = ByteArray(32) { (it + 1).toByte() }
        provider.unlock(key2)
        val derived2 = provider.deriveSubKey("room_passphrase_v1")

        assertFalse(derived1.contentEquals(derived2))
    }

    // Case 6: isUnlocked returns false initially and true after unlock.
    @Test
    fun `Given Case 6, When isUnlocked, Then returns correct state`() {
        assertFalse(provider.isUnlocked())
        provider.unlock(ByteArray(32))
        assertTrue(provider.isUnlocked())
    }

    // Case 7: isUnlocked returns false after lock.
    @Test
    fun `Given Case 7, When lock after unlock, Then isUnlocked returns false`() {
        provider.unlock(ByteArray(32))
        assertTrue(provider.isUnlocked())
        provider.lock()
        assertFalse(provider.isUnlocked())
    }

    // Case 8: getVaultKey returns null when locked and a copy when unlocked.
    @Test
    fun `Given Case 8, When getVaultKey, Then returns null when locked and copy when unlocked`() {
        assertNull(provider.getVaultKey())
        val key = ByteArray(32) { (it + 7).toByte() }
        provider.unlock(key)
        val returned = provider.getVaultKey()
        assertTrue(returned!!.contentEquals(key))
        assertFalse(returned === key)
    }

    // Case 9: lock zeroes the vault key (getVaultKey returns null).
    @Test
    fun `Given Case 9, When lock, Then getVaultKey returns null`() {
        provider.unlock(ByteArray(32))
        provider.lock()
        assertNull(provider.getVaultKey())
    }

    // Case 10: deriveSubKey throws after lock.
    @Test(expected = IllegalStateException::class)
    fun `Given Case 10, When deriveSubKey after lock, Then throws IllegalStateException`() {
        provider.unlock(ByteArray(32))
        provider.lock()
        provider.deriveSubKey("room_passphrase_v1")
    }
}
