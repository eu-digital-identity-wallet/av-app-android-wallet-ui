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

package eu.europa.ec.authenticationlogic.controller.authentication

import junit.framework.TestCase.assertEquals
import junit.framework.TestCase.assertFalse
import junit.framework.TestCase.assertTrue
import org.junit.Test

class TestBiometricVaultResult {

    @Test
    fun `Given Case 1, When BiometricVaultResult Success is created, Then it equals Success`() {
        val result = BiometricVaultResult.Success
        assertEquals(BiometricVaultResult.Success, result)
    }

    @Test
    fun `Given Case 2, When BiometricVaultResult Failed is created, Then message is preserved`() {
        val msg = "some error"
        val result = BiometricVaultResult.Failed(msg)
        assertEquals(msg, result.errorMessage)
    }

    @Test
    fun `Given Case 3, When BiometricVaultResult Cancelled is created, Then it equals Cancelled`() {
        val result = BiometricVaultResult.Cancelled
        assertEquals(BiometricVaultResult.Cancelled, result)
    }

    @Test
    fun `Given Case 4, When BiometricVaultResult KeyInvalidated is created, Then it equals KeyInvalidated`() {
        val result = BiometricVaultResult.KeyInvalidated
        assertEquals(BiometricVaultResult.KeyInvalidated, result)
    }

    @Test
    fun `Given Case 5, When comparing vault result types, Then they are distinct`() {
        assertFalse(BiometricVaultResult.Success.equals(BiometricVaultResult.Cancelled))
        assertFalse(BiometricVaultResult.Success.equals(BiometricVaultResult.KeyInvalidated))
        assertFalse(BiometricVaultResult.Cancelled.equals(BiometricVaultResult.KeyInvalidated))
        assertTrue(BiometricVaultResult.Failed("a") != BiometricVaultResult.Failed("b") as Any)
    }

    @Test
    fun `Given Case 6, When pattern matching on vault results, Then all cases are handled`() {
        val results = listOf(
            BiometricVaultResult.Success,
            BiometricVaultResult.Failed("error"),
            BiometricVaultResult.Cancelled,
            BiometricVaultResult.KeyInvalidated,
        )
        val labels = results.map {
            when (it) {
                is BiometricVaultResult.Success -> "success"
                is BiometricVaultResult.Failed -> "failed"
                is BiometricVaultResult.Cancelled -> "cancelled"
                is BiometricVaultResult.KeyInvalidated -> "key_invalidated"
            }
        }
        assertEquals(listOf("success", "failed", "cancelled", "key_invalidated"), labels)
    }
}
