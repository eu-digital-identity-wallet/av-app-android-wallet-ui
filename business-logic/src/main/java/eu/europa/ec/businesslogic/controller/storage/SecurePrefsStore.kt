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

package eu.europa.ec.businesslogic.controller.storage

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Replacement for the deprecated EncryptedSharedPreferences. Keys are HMAC-SHA256'd with a
 * Keystore-held HMAC key (av_prefs_index_v1) so on-disk filenames reveal no semantics. Values are
 * AES-256-GCM encrypted with a separate Keystore-held wrap key (av_prefs_wrap_v1). Both keys
 * prefer StrongBox with a graceful TEE fallback.
 */
internal class SecurePrefsStore(private val context: Context) {

    companion object {
        private const val PREFS_FILE = "av_secure_prefs"
        private const val WRAP_KEY_ALIAS = "av_prefs_wrap_v1"
        private const val INDEX_KEY_ALIAS = "av_prefs_index_v1"
        private const val GCM_IV_SIZE = 12
        private const val GCM_TAG_SIZE_BITS = 128
        private const val STORE_TYPE = "AndroidKeyStore"
    }

    private val plainPrefs by lazy {
        context.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE)
    }

    private val wrapKey: SecretKey by lazy { getOrCreateAesKey(WRAP_KEY_ALIAS) }
    private val indexKey: SecretKey by lazy { getOrCreateHmacKey(INDEX_KEY_ALIAS) }

    private fun keyStore(): KeyStore = KeyStore.getInstance(STORE_TYPE).also { it.load(null) }

    private fun getOrCreateAesKey(alias: String): SecretKey {
        val ks = keyStore()
        if (ks.containsAlias(alias)) return ks.getKey(alias, null) as SecretKey
        return generateAesKey(alias, tryStrongBox = true)
    }

    private fun generateAesKey(alias: String, tryStrongBox: Boolean): SecretKey {
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(false)
            .setIsStrongBoxBacked(tryStrongBox)
        return try {
            val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, STORE_TYPE)
            keyGen.init(builder.build())
            keyGen.generateKey()
            keyStore().getKey(alias, null) as SecretKey
        } catch (e: StrongBoxUnavailableException) {
            if (tryStrongBox) generateAesKey(alias, tryStrongBox = false) else throw e
        }
    }

    private fun getOrCreateHmacKey(alias: String): SecretKey {
        val ks = keyStore()
        if (ks.containsAlias(alias)) return ks.getKey(alias, null) as SecretKey
        return generateHmacKey(alias, tryStrongBox = true)
    }

    private fun generateHmacKey(alias: String, tryStrongBox: Boolean): SecretKey {
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setIsStrongBoxBacked(tryStrongBox)
        return try {
            val keyGen =
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, STORE_TYPE)
            keyGen.init(builder.build())
            keyGen.generateKey()
            keyStore().getKey(alias, null) as SecretKey
        } catch (e: StrongBoxUnavailableException) {
            if (tryStrongBox) generateHmacKey(alias, tryStrongBox = false) else throw e
        }
    }

    private fun hashKey(name: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(indexKey)
        return mac.doFinal(name.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }

    private fun encryptBytes(plaintext: ByteArray): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, wrapKey)
        val combined = cipher.iv + cipher.doFinal(plaintext)
        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    private fun decryptBytes(encoded: String): ByteArray? {
        return try {
            val combined = Base64.decode(encoded, Base64.NO_WRAP)
            if (combined.size <= GCM_IV_SIZE) return null
            val iv = combined.copyOfRange(0, GCM_IV_SIZE)
            val ciphertext = combined.copyOfRange(GCM_IV_SIZE, combined.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, wrapKey, GCMParameterSpec(GCM_TAG_SIZE_BITS, iv))
            cipher.doFinal(ciphertext)
        } catch (_: Exception) {
            null
        }
    }

    fun contains(key: String): Boolean = plainPrefs.contains(hashKey(key))

    fun clear(key: String) = plainPrefs.edit().remove(hashKey(key)).apply()

    fun clear() = plainPrefs.edit().clear().apply()

    fun setString(key: String, value: String) {
        plainPrefs.edit()
            .putString(hashKey(key), encryptBytes(value.toByteArray(Charsets.UTF_8)))
            .apply()
    }

    fun getString(key: String, default: String): String {
        val encoded = plainPrefs.getString(hashKey(key), null) ?: return default
        // Intended, must use toString(Charsets.UTF_8), not contentToString()
        return decryptBytes(encoded)?.toString(Charsets.UTF_8) ?: default
    }

    fun setLong(key: String, value: Long) = setString(key, value.toString())

    fun getLong(key: String, default: Long): Long {
        val s = getString(key, "")
        return if (s.isEmpty()) default else s.toLongOrNull() ?: default
    }

    fun setBool(key: String, value: Boolean) = setString(key, value.toString())

    fun getBool(key: String, default: Boolean): Boolean {
        val s = getString(key, "")
        return if (s.isEmpty()) default else s.toBooleanStrictOrNull() ?: default
    }

    fun setInt(key: String, value: Int) = setString(key, value.toString())

    fun getInt(key: String, default: Int): Int {
        val s = getString(key, "")
        return if (s.isEmpty()) default else s.toIntOrNull() ?: default
    }
}
