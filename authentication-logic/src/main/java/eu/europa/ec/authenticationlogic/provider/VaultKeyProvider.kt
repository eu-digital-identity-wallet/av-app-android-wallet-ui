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

package eu.europa.ec.authenticationlogic.provider

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

interface VaultKeyProvider {
    val unlocked: StateFlow<Boolean>
    fun unlock(vaultKey: ByteArray)
    fun lock()
    fun isUnlocked(): Boolean
    fun getVaultKey(): ByteArray?
    fun deriveSubKey(featureLabel: String): ByteArray
}

class VaultKeyProviderImpl : VaultKeyProvider {

    companion object {
        private const val HMAC_ALGO = "HmacSHA256"
        private const val HASH_LEN = 32
    }

    private val _unlocked = MutableStateFlow(false)
    override val unlocked: StateFlow<Boolean> = _unlocked.asStateFlow()
    @Synchronized
    override fun isUnlocked(): Boolean = _unlocked.value
    @Volatile
    private var vaultKey: ByteArray? = null
    @Synchronized
    override fun unlock(vaultKey: ByteArray) {
        this.vaultKey = vaultKey.copyOf()
        _unlocked.value = true
    }

    @Synchronized
    override fun lock() {
        vaultKey?.fill(0)
        vaultKey = null
        _unlocked.value = false
    }

    @Synchronized
    override fun getVaultKey(): ByteArray? = vaultKey?.copyOf()
    @Synchronized
    override fun deriveSubKey(featureLabel: String): ByteArray {
        val ikm = vaultKey ?: throw IllegalStateException("Vault key not available")
        val salt = ByteArray(HASH_LEN)
        val mac = Mac.getInstance(HMAC_ALGO)
        mac.init(SecretKeySpec(salt, HMAC_ALGO))
        val prk = mac.doFinal(ikm)
        mac.init(SecretKeySpec(prk, HMAC_ALGO))
        val info = featureLabel.toByteArray(Charsets.UTF_8)
        val okm = mac.doFinal(info + byteArrayOf(0x01))
        return okm.copyOf(HASH_LEN)
    }
}
