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

import java.nio.ByteBuffer
import java.nio.ByteOrder

internal object AuthMetadataCodec {

    private const val CURRENT_VERSION: Byte = 0x01
    private const val WRAPPED_VAULT_IV_SIZE = 12

    fun encode(meta: AuthMetadata): ByteArray {
        require(meta.wrappedVaultIv.size == WRAPPED_VAULT_IV_SIZE) {
            "wrappedVaultIv must be $WRAPPED_VAULT_IV_SIZE bytes, got ${meta.wrappedVaultIv.size}"
        }
        require(meta.biometricWrappedVaultIv == null || meta.biometricWrappedVaultIv.size == WRAPPED_VAULT_IV_SIZE) {
            "biometricWrappedVaultIv must be $WRAPPED_VAULT_IV_SIZE bytes, got ${meta.biometricWrappedVaultIv?.size}"
        }
        val bootIdBytes = meta.bootId.toByteArray(Charsets.UTF_8)
        val hasBio = meta.biometricEnabled &&
            meta.biometricWrappedVaultIv != null &&
            meta.biometricWrappedVault != null

        val capacity = 1 + 1 + 4 + 4 + 4 +
            4 + meta.pinSalt.size +
            WRAPPED_VAULT_IV_SIZE +
            4 + meta.wrappedVault.size +
            4 + 8 + 8 +
            4 + bootIdBytes.size +
            1 +
            (if (hasBio) WRAPPED_VAULT_IV_SIZE + 4 + (meta.biometricWrappedVault.size) else 0) +
            8

        val buf = ByteBuffer.allocate(capacity).order(ByteOrder.BIG_ENDIAN)
        buf.put(meta.version)
        buf.put(meta.kdfAlgo)
        buf.putInt(meta.kdfM)
        buf.putInt(meta.kdfT)
        buf.putInt(meta.kdfP)
        buf.putInt(meta.pinSalt.size)
        buf.put(meta.pinSalt)
        buf.put(meta.wrappedVaultIv)
        buf.putInt(meta.wrappedVault.size)
        buf.put(meta.wrappedVault)
        buf.putInt(meta.failedAttempts)
        buf.putLong(meta.lockoutDeadline)
        buf.putLong(meta.lockoutDuration)
        buf.putInt(bootIdBytes.size)
        buf.put(bootIdBytes)
        buf.put(if (hasBio) 0x01.toByte() else 0x00.toByte())
        if (hasBio) {
            buf.put(meta.biometricWrappedVaultIv)
            buf.putInt(meta.biometricWrappedVault.size)
            buf.put(meta.biometricWrappedVault)
        }
        buf.putLong(meta.writeCounter)
        return buf.array()
    }

    fun decode(bytes: ByteArray): AuthMetadata {
        try {
            val buf = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
            val version = buf.get()
            if (version != CURRENT_VERSION) {
                throw AuthMetadataCorruptException("Unknown version: $version")
            }
            val kdfAlgo = buf.get()
            val kdfM = buf.getInt()
            val kdfT = buf.getInt()
            val kdfP = buf.getInt()
            val pinSaltLen = buf.getInt()
            val pinSalt = ByteArray(pinSaltLen).also { buf.get(it) }
            val wrappedVaultIv = ByteArray(WRAPPED_VAULT_IV_SIZE).also { buf.get(it) }
            val wrappedVaultLen = buf.getInt()
            val wrappedVault = ByteArray(wrappedVaultLen).also { buf.get(it) }
            val failedAttempts = buf.getInt()
            val lockoutDeadline = buf.getLong()
            val lockoutDuration = buf.getLong()
            val bootIdLen = buf.getInt()
            val bootId = ByteArray(bootIdLen).also { buf.get(it) }.toString(Charsets.UTF_8)
            val biometricEnabled = buf.get() == 0x01.toByte()
            val biometricWrappedVaultIv: ByteArray?
            val biometricWrappedVault: ByteArray?
            if (biometricEnabled) {
                biometricWrappedVaultIv = ByteArray(WRAPPED_VAULT_IV_SIZE).also { buf.get(it) }
                val bioLen = buf.getInt()
                biometricWrappedVault = ByteArray(bioLen).also { buf.get(it) }
            } else {
                biometricWrappedVaultIv = null
                biometricWrappedVault = null
            }
            val writeCounter = buf.getLong()
            return AuthMetadata(
                version = version,
                kdfAlgo = kdfAlgo,
                kdfM = kdfM,
                kdfT = kdfT,
                kdfP = kdfP,
                pinSalt = pinSalt,
                wrappedVaultIv = wrappedVaultIv,
                wrappedVault = wrappedVault,
                bootId = bootId,
                failedAttempts = failedAttempts,
                lockoutDeadline = lockoutDeadline,
                lockoutDuration = lockoutDuration,
                biometricEnabled = biometricEnabled,
                biometricWrappedVaultIv = biometricWrappedVaultIv,
                biometricWrappedVault = biometricWrappedVault,
                writeCounter = writeCounter,
            )
        } catch (e: AuthMetadataCorruptException) {
            throw e
        } catch (e: Exception) {
            throw AuthMetadataCorruptException("Failed to decode AuthMetadata: ${e.message}")
        }
    }
}
