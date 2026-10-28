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

package eu.europa.ec.corelogic.controller

import eu.europa.ec.authenticationlogic.provider.VaultKeyProvider
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.businesslogic.provider.UuidProvider
import eu.europa.ec.eudi.wallet.transactionLogging.TransactionLog
import eu.europa.ec.storagelogic.dao.TransactionLogDao
import eu.europa.ec.storagelogic.storage.DatabaseManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.mockito.Mock
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.any
import org.mockito.kotlin.never
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.UUID

class TestWalletCoreTransactionLogControllerImpl {

    @Mock
    private lateinit var databaseManager: DatabaseManager

    @Mock
    private lateinit var vaultKeyProvider: VaultKeyProvider

    @Mock
    private lateinit var logController: LogController

    @Mock
    private lateinit var uuidProvider: UuidProvider

    @Mock
    private lateinit var transactionLogDao: TransactionLogDao

    private lateinit var closeable: AutoCloseable

    @Before
    fun before() {
        closeable = MockitoAnnotations.openMocks(this)
        whenever(uuidProvider.provideUuid()).thenReturn(UUID.randomUUID().toString())
    }

    @After
    fun after() {
        closeable.close()
    }

    private fun newController(scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)): WalletCoreTransactionLogControllerImpl =
        WalletCoreTransactionLogControllerImpl(
            databaseManager = databaseManager,
            vaultKeyProvider = vaultKeyProvider,
            logController = logController,
            scope = scope,
            uuidProvider = uuidProvider
        )

    private fun sampleTransaction(): TransactionLog = TransactionLog(
        timestamp = 0L,
        status = TransactionLog.Status.Incomplete,
        type = TransactionLog.Type.Presentation,
        relyingParty = null,
        rawRequest = null,
        rawResponse = null,
        dataFormat = TransactionLog.DataFormat.Json,
        sessionTranscript = null,
        metadata = emptyList()
    )

    // Case 1: vault locked -> log() drops the transaction and never touches the DB.
    // Covers AC #1, #3 (decline / error while locked -> no DB open -> no crash).
    @Test
    fun `Given locked vault, When log, Then transaction is dropped and DB is never opened`() = runBlocking {
        val controller = newController()

        whenever(vaultKeyProvider.isUnlocked()).thenReturn(false)

        controller.log(sampleTransaction())

        verify(logController, times(1)).w(any())
        verify(databaseManager, never()).transactionLogDao()
        verify(transactionLogDao, never()).store(any())
    }

    // Case 2: vault unlocked -> log() stores the transaction with a fresh UUID identifier.
    // Covers AC #6 (decline while unlocked keeps storing the transaction log).
    @Test
    fun `Given unlocked vault, When log, Then transaction is stored`() = runBlocking {
        whenever(databaseManager.transactionLogDao()).thenReturn(transactionLogDao)
        val controller = newController()

        whenever(vaultKeyProvider.isUnlocked()).thenReturn(true)

        controller.log(sampleTransaction())

        verify(transactionLogDao, times(1)).store(any())
        verify(logController, never()).e(any<Throwable>(), any())
    }

    // Case 3: store throws while unlocked -> log() swallows it and logs an error,
    // the process does not crash. Covers AC #4 second clause.
    @Test
    fun `Given unlocked vault and store throws, When log, Then error is logged and no crash`() = runBlocking {
        whenever(databaseManager.transactionLogDao()).thenReturn(transactionLogDao)
        val controller = newController()

        whenever(vaultKeyProvider.isUnlocked()).thenReturn(true)
        whenever(transactionLogDao.store(any())).thenAnswer {
            throw IllegalStateException("Vault key not available")
        }

        // Must not throw.
        controller.log(sampleTransaction())

        verify(logController, times(1)).e(any<Throwable>(), any())
        verify(transactionLogDao, times(1)).store(any())
    }
}
