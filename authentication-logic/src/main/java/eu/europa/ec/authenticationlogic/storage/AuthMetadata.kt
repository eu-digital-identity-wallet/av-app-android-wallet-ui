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

data class AuthMetadata(
    val version: Byte,
    val kdfAlgo: Byte,
    val kdfM: Int,
    val kdfT: Int,
    val kdfP: Int,
    val pinSalt: ByteArray,
    val wrappedVaultIv: ByteArray,
    val wrappedVault: ByteArray,
    val bootId: String,
    val failedAttempts: Int = 0,
    val lockoutDeadline: Long = 0,
    val lockoutDuration: Long = 0,
    val biometricEnabled: Boolean = false,
    val biometricWrappedVaultIv: ByteArray? = null,
    val biometricWrappedVault: ByteArray? = null,
    val writeCounter: Long = 0L,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AuthMetadata) return false
        return version == other.version &&
            kdfAlgo == other.kdfAlgo &&
            kdfM == other.kdfM &&
            kdfT == other.kdfT &&
            kdfP == other.kdfP &&
            pinSalt.contentEquals(other.pinSalt) &&
            wrappedVaultIv.contentEquals(other.wrappedVaultIv) &&
            wrappedVault.contentEquals(other.wrappedVault) &&
            failedAttempts == other.failedAttempts &&
            lockoutDeadline == other.lockoutDeadline &&
            lockoutDuration == other.lockoutDuration &&
            bootId == other.bootId &&
            biometricEnabled == other.biometricEnabled &&
            (biometricWrappedVaultIv == null) == (other.biometricWrappedVaultIv == null) &&
            (biometricWrappedVaultIv == null || biometricWrappedVaultIv.contentEquals(other.biometricWrappedVaultIv!!)) &&
            (biometricWrappedVault == null) == (other.biometricWrappedVault == null) &&
            (biometricWrappedVault == null || biometricWrappedVault.contentEquals(other.biometricWrappedVault!!)) &&
            writeCounter == other.writeCounter
    }

    override fun toString(): String =
        "AuthMetadata(version=$version, kdfAlgo=$kdfAlgo, kdfM=$kdfM, kdfT=$kdfT, kdfP=$kdfP, " +
            "pinSalt=[REDACTED], wrappedVaultIv=[REDACTED], wrappedVault=[REDACTED], " +
            "failedAttempts=$failedAttempts, lockoutDeadline=$lockoutDeadline, " +
            "lockoutDuration=$lockoutDuration, bootId=$bootId, biometricEnabled=$biometricEnabled, " +
            "biometricWrappedVaultIv=[REDACTED], biometricWrappedVault=[REDACTED], " +
            "writeCounter=$writeCounter)"

    override fun hashCode(): Int {
        var result = version.toInt()
        result = 31 * result + kdfAlgo
        result = 31 * result + kdfM
        result = 31 * result + kdfT
        result = 31 * result + kdfP
        result = 31 * result + pinSalt.contentHashCode()
        result = 31 * result + wrappedVaultIv.contentHashCode()
        result = 31 * result + wrappedVault.contentHashCode()
        result = 31 * result + failedAttempts
        result = 31 * result + lockoutDeadline.hashCode()
        result = 31 * result + lockoutDuration.hashCode()
        result = 31 * result + bootId.hashCode()
        result = 31 * result + biometricEnabled.hashCode()
        result = 31 * result + (biometricWrappedVaultIv?.contentHashCode() ?: 0)
        result = 31 * result + (biometricWrappedVault?.contentHashCode() ?: 0)
        result = 31 * result + writeCounter.hashCode()
        return result
    }
}

class AuthMetadataCorruptException(message: String) : Exception(message)
