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

package eu.europa.ec.storagelogic.storage

import android.content.Context
import androidx.room.Room
import eu.europa.ec.authenticationlogic.provider.VaultKeyProvider
import eu.europa.ec.storagelogic.dao.BookmarkDao
import eu.europa.ec.storagelogic.dao.RevokedDocumentDao
import eu.europa.ec.storagelogic.dao.TransactionLogDao
import eu.europa.ec.storagelogic.service.DatabaseService
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory

class DatabaseManager(
    private val context: Context,
    private val vaultKeyProvider: VaultKeyProvider,
) {

    companion object {
        private const val DB_NAME = "eudi.app.wallet.storage"
        private const val PASSPHRASE_LABEL = "room_passphrase_v1"
    }

    @Volatile
    private var db: DatabaseService? = null

    @Synchronized
    fun getDatabase(): DatabaseService {
        db?.let { return it }
        val passphrase = vaultKeyProvider.deriveSubKey(PASSPHRASE_LABEL)
        System.loadLibrary("sqlcipher")
        val factory = SupportOpenHelperFactory(passphrase)
        val instance = Room.databaseBuilder(
            context,
            DatabaseService::class.java,
            DB_NAME
        )
            .openHelperFactory(factory)
            .fallbackToDestructiveMigration(true)
            .build()
        db = instance
        return instance
    }

    fun bookmarkDao(): BookmarkDao = getDatabase().bookmarkDao()

    fun revokedDocumentDao(): RevokedDocumentDao = getDatabase().revokedDocumentDao()

    fun transactionLogDao(): TransactionLogDao = getDatabase().transactionLogDao()

    @Synchronized
    fun close() {
        db?.close()
        db = null
    }
}
