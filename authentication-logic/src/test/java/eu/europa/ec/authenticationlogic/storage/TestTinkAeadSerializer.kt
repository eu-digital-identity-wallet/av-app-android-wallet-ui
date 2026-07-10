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

import androidx.datastore.core.CorruptionException
import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.RegistryConfiguration
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.aead.AesGcmParameters
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import junit.framework.TestCase.assertTrue
import kotlinx.coroutines.test.runTest
import org.junit.Before
import org.junit.Test

class TestTinkAeadSerializer {

    private lateinit var aead: Aead
    private lateinit var serializer: TinkAeadSerializer

    @Before
    fun before() {
        AeadConfig.register()
        val parameters = AesGcmParameters.builder()
            .setKeySizeBytes(32)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build()
        aead = KeysetHandle.generateNew(parameters)
            .getPrimitive(RegistryConfiguration.get(), Aead::class.java)
        serializer = TinkAeadSerializer(aead)
    }

    @Test
    fun `Given write then read, When round-trip, Then original bytes are returned`() = runTest {
        val original = "test-auth-data".toByteArray()
        val output = ByteArrayOutputStream()
        serializer.writeTo(original, output)
        val input = ByteArrayInputStream(output.toByteArray())
        val result = serializer.readFrom(input)
        assertTrue(original.contentEquals(result))
    }

    @Test
    fun `Given empty input, When read, Then default value is returned`() = runTest {
        val input = ByteArrayInputStream(ByteArray(0))
        val result = serializer.readFrom(input)
        assertTrue(result.isEmpty())
    }

    @Test
    fun `Given corrupted ciphertext, When read, Then CorruptionException is thrown`() = runTest {
        val output = ByteArrayOutputStream()
        serializer.writeTo("data".toByteArray(), output)
        val bytes = output.toByteArray()
        val corrupted = ByteArray(bytes.size) { i ->
            (bytes[i].toInt() xor 0xFF).toByte()
        }
        val input = ByteArrayInputStream(corrupted)
        var threw = false
        try {
            serializer.readFrom(input)
        } catch (_: CorruptionException) {
            threw = true
        }
        assertTrue(threw)
    }

    @Test
    fun `Given defaultValue, When write then read, Then empty array is returned`() = runTest {
        val output = ByteArrayOutputStream()
        serializer.writeTo(ByteArray(0), output)
        val input = ByteArrayInputStream(output.toByteArray())
        val result = serializer.readFrom(input)
        assertTrue(result.isEmpty())
    }

    @Test
    fun `Given large payload, When write then read, Then original bytes are returned`() = runTest {
        val original = ByteArray(4096) { it.toByte() }
        val output = ByteArrayOutputStream()
        serializer.writeTo(original, output)
        val input = ByteArrayInputStream(output.toByteArray())
        val result = serializer.readFrom(input)
        assertTrue(original.contentEquals(result))
    }
}
