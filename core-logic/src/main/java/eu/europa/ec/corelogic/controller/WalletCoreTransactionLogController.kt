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
import eu.europa.ec.businesslogic.provider.UuidProvider
import eu.europa.ec.eudi.wallet.transactionLogging.TransactionLog
import eu.europa.ec.eudi.wallet.transactionLogging.TransactionLogger
import eu.europa.ec.storagelogic.storage.DatabaseManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlin.uuid.ExperimentalUuidApi
import eu.europa.ec.storagelogic.model.TransactionLog as TransactionStorage

interface WalletCoreTransactionLogController : TransactionLogger

class WalletCoreTransactionLogControllerImpl(
    private val databaseManager: DatabaseManager,
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
    private val uuidProvider: UuidProvider
) : WalletCoreTransactionLogController {

    @OptIn(ExperimentalUuidApi::class)
    override fun log(transaction: TransactionLog) {
        scope.launch {
            val json = Gson().toJson(transaction)
            databaseManager.transactionLogDao().store(
                TransactionStorage(
                    identifier = uuidProvider.provideUuid(),
                    value = json
                )
            )
        }
    }
}