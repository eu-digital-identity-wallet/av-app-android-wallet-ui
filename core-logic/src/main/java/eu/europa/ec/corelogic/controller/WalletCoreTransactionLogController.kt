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

package eu.europa.ec.corelogic.controller

import com.nimbusds.jose.shaded.gson.Gson
import eu.europa.ec.authenticationlogic.provider.VaultKeyProvider
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.businesslogic.provider.UuidProvider
import eu.europa.ec.eudi.wallet.transactionLogging.TransactionLog
import eu.europa.ec.eudi.wallet.transactionLogging.TransactionLogger
import eu.europa.ec.storagelogic.storage.DatabaseManager
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlin.uuid.ExperimentalUuidApi
import eu.europa.ec.storagelogic.model.TransactionLog as TransactionStorage

interface WalletCoreTransactionLogController : TransactionLogger

class WalletCoreTransactionLogControllerImpl(
    private val databaseManager: DatabaseManager,
    private val vaultKeyProvider: VaultKeyProvider,
    private val logController: LogController,
    private val scope: CoroutineScope = CoroutineScope(
        SupervisorJob() + Dispatchers.IO + CoroutineExceptionHandler { _, throwable ->
            logController.e(throwable) { "Transaction log coroutine failed" }
        }
    ),
    private val uuidProvider: UuidProvider
) : WalletCoreTransactionLogController {

    @OptIn(ExperimentalUuidApi::class)
    override fun log(transaction: TransactionLog) {
        if (!vaultKeyProvider.isUnlocked()) {
            logController.w { "Transaction log dropped: vault is locked" }
            return
        }

        scope.launch {
            try {
                val json = Gson().toJson(transaction)
                databaseManager.transactionLogDao().store(
                    TransactionStorage(
                        identifier = uuidProvider.provideUuid(),
                        value = json
                    )
                )
            } catch (throwable: Throwable) {
                logController.e(throwable) { "Failed to store transaction log" }
            }
        }
    }
}
