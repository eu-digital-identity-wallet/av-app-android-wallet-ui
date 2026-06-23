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

package eu.europa.ec.landingfeature.interactor

import eu.europa.ec.corelogic.controller.DeleteAllDocumentsPartialState
import eu.europa.ec.corelogic.controller.WalletCoreDocumentsController
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow

interface SettingsInteractor {
    fun deleteAllDocuments(): Flow<DeleteAgeDocumentsPartialState>
}

sealed class DeleteAgeDocumentsPartialState {
    object Success : DeleteAgeDocumentsPartialState()
    data class Failure(val errorMessage: String) : DeleteAgeDocumentsPartialState()
    object NoDocuments : DeleteAgeDocumentsPartialState()
}

class SettingsInteractorImpl(
    private val walletCoreDocumentsController: WalletCoreDocumentsController
) : SettingsInteractor {
    private fun hasDocuments(): Boolean = walletCoreDocumentsController.hasIssuedDocuments()

    override fun deleteAllDocuments(): Flow<DeleteAgeDocumentsPartialState> = flow {
        if (!hasDocuments()) {
            emit(DeleteAgeDocumentsPartialState.NoDocuments)
            return@flow
        }
        walletCoreDocumentsController.deleteAllAgeDocuments().collect { state ->
            when (state) {
                is DeleteAllDocumentsPartialState.Success -> {
                    emit(DeleteAgeDocumentsPartialState.Success)
                }
                is DeleteAllDocumentsPartialState.Failure -> {
                    emit(DeleteAgeDocumentsPartialState.Failure(state.errorMessage))
                }
            }
        }
    }
}
