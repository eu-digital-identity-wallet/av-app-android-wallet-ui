/*
 * Copyright (c) 2023 European Commission
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

package eu.europa.ec.storagelogic.di

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import androidx.room.Room
import eu.europa.ec.storagelogic.dao.BookmarkDao
import eu.europa.ec.storagelogic.dao.RevokedDocumentDao
import eu.europa.ec.storagelogic.dao.TransactionLogDao
import eu.europa.ec.storagelogic.service.DatabaseService
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import org.koin.core.annotation.ComponentScan
import org.koin.core.annotation.Module
import org.koin.core.annotation.Single
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

@Module
@ComponentScan("eu.europa.ec.storagelogic")
class LogicStorageModule

@Single
fun provideAppDatabase(context: Context): DatabaseService {
    System.loadLibrary("sqlcipher")
    val passphrase = getOrCreateDbPassphrase(context)
    val factory = SupportOpenHelperFactory(passphrase)
    return Room.databaseBuilder(
        context,
        DatabaseService::class.java,
        "eudi.app.wallet.storage"
    )
        .openHelperFactory(factory)
        // Intentional: this is a template repository with no shipped user data to preserve.
        // Teams forking for production must replace this with explicit Migration objects.
        .fallbackToDestructiveMigration(true)
        .build()
}

private const val DB_KEY_PREFS = "db-key-prefs"
private const val DB_PASSPHRASE_KEY = "db_passphrase_v2"
private const val DB_KEY_ALIAS = "av_db_wrap_v1"
private const val GCM_IV_SIZE = 12
private const val GCM_TAG_SIZE_BITS = 128
private const val STORE_TYPE = "AndroidKeyStore"

private fun getOrCreateDbPassphrase(context: Context): ByteArray {
    val plainPrefs =
        context.getSharedPreferences("${DB_KEY_PREFS}_plain", Context.MODE_PRIVATE)
    val wrapKey = getOrCreateDbWrapKey()
    val stored = plainPrefs.getString(DB_PASSPHRASE_KEY, null)
    if (stored != null) {
        val decoded = Base64.decode(stored, Base64.NO_WRAP)
        if (decoded.size > GCM_IV_SIZE) {
            val decrypted = tryDecrypt(wrapKey, decoded)
            if (decrypted != null) return decrypted
            // Keystore key lost (most likely backup/restore to a new device — Keystore keys are
            // hardware-bound and are never included in Android backups). The encrypted blob is
            // unreadable, so wipe it and generate a fresh passphrase. Room's
            // fallbackToDestructiveMigration will recreate the database on next open.
            plainPrefs.edit().remove(DB_PASSPHRASE_KEY).apply()
        }
    }
    val passphrase = ByteArray(32).also { SecureRandom().nextBytes(it) }
    val encrypted = encrypt(wrapKey, passphrase)
    plainPrefs.edit().putString(DB_PASSPHRASE_KEY, Base64.encodeToString(encrypted, Base64.NO_WRAP))
        .apply()
    return passphrase
}

private fun getOrCreateDbWrapKey(): SecretKey {
    val ks = KeyStore.getInstance(STORE_TYPE).also { it.load(null) }
    if (ks.containsAlias(DB_KEY_ALIAS)) return ks.getKey(DB_KEY_ALIAS, null) as SecretKey
    return generateDbWrapKey(tryStrongBox = true)
}

private fun generateDbWrapKey(tryStrongBox: Boolean): SecretKey {
    val builder = KeyGenParameterSpec.Builder(
        DB_KEY_ALIAS,
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
        KeyStore.getInstance(STORE_TYPE).also { it.load(null) }.getKey(DB_KEY_ALIAS, null) as SecretKey
    } catch (e: StrongBoxUnavailableException) {
        if (tryStrongBox) generateDbWrapKey(tryStrongBox = false) else throw e
    }
}

private fun encrypt(key: SecretKey, plaintext: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key)
    return cipher.iv + cipher.doFinal(plaintext)
}

private fun tryDecrypt(key: SecretKey, combined: ByteArray): ByteArray? {
    return try {
        val iv = combined.copyOfRange(0, GCM_IV_SIZE)
        val ciphertext = combined.copyOfRange(GCM_IV_SIZE, combined.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_SIZE_BITS, iv))
        cipher.doFinal(ciphertext)
    } catch (_: Exception) {
        null
    }
}

@Single
fun provideBookmarkDao(service: DatabaseService): BookmarkDao = service.bookmarkDao()

@Single
fun provideRevokedDocumentDao(service: DatabaseService): RevokedDocumentDao =
    service.revokedDocumentDao()

@Single
fun provideTransactionLogDao(service: DatabaseService): TransactionLogDao =
    service.transactionLogDao()
