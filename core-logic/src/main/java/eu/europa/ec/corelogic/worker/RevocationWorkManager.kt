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

package eu.europa.ec.corelogic.worker

import android.content.Context
import android.content.Intent
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import eu.europa.ec.authenticationlogic.provider.VaultKeyProvider
import eu.europa.ec.businesslogic.util.InProcessEventBus
import eu.europa.ec.corelogic.controller.WalletCoreDocumentsController
import eu.europa.ec.corelogic.model.RevokedDocumentDataDomain
import eu.europa.ec.corelogic.util.CoreActions
import eu.europa.ec.corelogic.util.CoreActions.REVOCATION_IDS_DETAILS_EXTRA
import eu.europa.ec.eudi.statium.Status
import eu.europa.ec.eudi.wallet.document.IssuedDocument
import eu.europa.ec.storagelogic.model.RevokedDocument
import eu.europa.ec.storagelogic.storage.DatabaseManager
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject

/**
 * [RevocationWorkManager] is a [CoroutineWorker] responsible for checking the revocation status of issued documents
 * and updating the local storage and sending broadcasts when revocations are detected.
 *
 * It utilizes Koin for dependency injection to obtain instances of [eu.europa.ec.storagelogic.dao.RevokedDocumentDao] and [WalletCoreDocumentsController].
 *
 * Key functionalities:
 *  - Periodically retrieves all issued documents from the [WalletCoreDocumentsController].
 *  - Checks the status of each document for revocation using [WalletCoreDocumentsController.resolveDocumentStatus].
 *  - Identifies documents with statuses [Status.Invalid] or [Status.Suspended] as revoked.
 *  - Stores revoked documents in the [eu.europa.ec.storagelogic.dao.RevokedDocumentDao].
 *  - Sends three broadcasts to notify the application about the revoked documents:
 *      - `CoreActions.REVOCATION_WORK_MESSAGE_ACTION`: Includes a list of [RevokedDocumentPayload] with names and IDs.
 *      - `CoreActions.REVOCATION_WORK_REFRESH_ACTION`: A general refresh action without specific data.
 *      - `CoreActions.REVOCATION_WORK_REFRESH_DETAILS_ACTION`: Includes a list of revoked document IDs in `REVOCATION_IDS_DETAILS_EXTRA`.
 *
 *  The worker returns:
 *      - [Result.success] if the revocation check and updates were successful.
 *      - [Result.failure] if an [IllegalArgumentException] occurred during the process.  This indicates a configuration or data issue.
 *
 * @param appContext The application context.
 * @param workerParams Parameters for the worker.
 */
class RevocationWorkManager(
    appContext: Context,
    workerParams: WorkerParameters,
) : CoroutineWorker(appContext, workerParams), KoinComponent {

    private val vaultKeyProvider: VaultKeyProvider by inject()
    private val databaseManager: DatabaseManager by inject()
    private val walletCoreDocumentsController: WalletCoreDocumentsController by inject()

    companion object {
        const val REVOCATION_WORK_NAME = "revocationWorker"
    }

    override suspend fun doWork(): Result {
        try {
            if (vaultKeyProvider.isUnlocked()) {
                val storedRevokedDocuments = walletCoreDocumentsController.getRevokedDocumentIds()
                val fromRevokedToValid = mutableListOf<String>()
                val revokedDocuments = mutableListOf<IssuedDocument>()

                walletCoreDocumentsController
                    .getAllIssuedDocuments()
                    .forEach { document ->
                        walletCoreDocumentsController.resolveDocumentStatus(document).fold(
                            onSuccess = { status ->
                                when (status) {
                                    is Status.Invalid, Status.Suspended -> {
                                        if (!storedRevokedDocuments.any { it == document.id }) {
                                            revokedDocuments.add(document)
                                        }
                                    }

                                    is Status.Valid -> {
                                        if (storedRevokedDocuments.any { it == document.id }) {
                                            fromRevokedToValid.add(document.id)
                                        }
                                    }

                                    else -> {}
                                }
                            },
                            onFailure = {}
                        )
                    }

                if (fromRevokedToValid.isNotEmpty()) {
                    removeRevokedDocumentsFromStorage(fromRevokedToValid)
                }

                if (revokedDocuments.isNotEmpty()) {
                    storeRevokedDocuments(revokedDocuments)
                    sendRevocationBroadcasts(revokedDocuments)
                }

                if (fromRevokedToValid.isNotEmpty() || revokedDocuments.isNotEmpty()) {
                    notifyDocumentsList()
                }
            }

            return Result.success()
        } catch (_: IllegalArgumentException) {
            return Result.failure()
        }
    }

    @Throws(IllegalArgumentException::class)
    private suspend fun storeRevokedDocuments(revokedDocuments: List<IssuedDocument>) {
        databaseManager.revokedDocumentDao().storeAll(
            revokedDocuments.map { RevokedDocument(identifier = it.id) }
        )
    }

    @Throws(IllegalArgumentException::class)
    private suspend fun removeRevokedDocumentsFromStorage(ids: List<String>) {
        ids.forEach {
            databaseManager.revokedDocumentDao().delete(it)
        }
    }

    private fun sendRevocationBroadcasts(revokedDocuments: List<IssuedDocument>) {

        val messageIntent = Intent(CoreActions.REVOCATION_WORK_MESSAGE_ACTION).apply {
            putParcelableArrayListExtra(
                CoreActions.REVOCATION_IDS_EXTRA,
                ArrayList(
                    revokedDocuments.map {
                        RevokedDocumentDataDomain(name = it.name, id = it.id)
                    }
                )
            )
        }

        val detailsIntent = Intent(CoreActions.REVOCATION_WORK_REFRESH_DETAILS_ACTION).apply {
            putStringArrayListExtra(
                REVOCATION_IDS_DETAILS_EXTRA,
                ArrayList(
                    revokedDocuments.map { it.id }
                )
            )
        }

        InProcessEventBus.send(messageIntent)
        InProcessEventBus.send(detailsIntent)
    }

    private fun notifyDocumentsList() {
        val refreshIntent = Intent(CoreActions.REVOCATION_WORK_REFRESH_ACTION)
        InProcessEventBus.send(refreshIntent)
    }
}
