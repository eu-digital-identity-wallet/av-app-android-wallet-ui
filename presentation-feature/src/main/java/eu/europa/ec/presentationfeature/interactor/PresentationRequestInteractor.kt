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

package eu.europa.ec.presentationfeature.interactor

import android.content.Context
import eu.europa.ec.businesslogic.extension.safeAsync
import eu.europa.ec.businesslogic.extension.toErrorType
import eu.europa.ec.businesslogic.model.ErrorType
import eu.europa.ec.authenticationlogic.provider.VaultKeyProvider
import eu.europa.ec.businesslogic.provider.UuidProvider
import eu.europa.ec.commonfeature.config.PresentationMode.DcApi as DcApiPresentationMode
import eu.europa.ec.commonfeature.config.RequestUriConfig
import eu.europa.ec.commonfeature.config.toDomainConfig
import eu.europa.ec.commonfeature.ui.request.model.DocumentPayloadDomain
import eu.europa.ec.commonfeature.ui.request.model.RequestDocumentItemUi
import eu.europa.ec.commonfeature.ui.request.transformer.RequestTransformer
import eu.europa.ec.corelogic.config.WalletCoreConfig
import eu.europa.ec.corelogic.controller.PresentationControllerConfig.DcApi as DcApiPresentationControllerConfig
import eu.europa.ec.corelogic.controller.TransferEventPartialState.Disconnected
import eu.europa.ec.corelogic.controller.TransferEventPartialState.Error
import eu.europa.ec.corelogic.controller.TransferEventPartialState.RequestReceived
import eu.europa.ec.corelogic.controller.WalletCoreDocumentsController
import eu.europa.ec.corelogic.controller.WalletCorePresentationController
import eu.europa.ec.presentationfeature.interactor.PresentationRequestInteractorPartialState.Disconnect
import eu.europa.ec.presentationfeature.interactor.PresentationRequestInteractorPartialState.Failure
import eu.europa.ec.presentationfeature.interactor.PresentationRequestInteractorPartialState.NoData
import eu.europa.ec.presentationfeature.interactor.PresentationRequestInteractorPartialState.Success
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.uilogic.navigation.helper.DcApiIntentHolder
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.mapNotNull

sealed class PresentationRequestInteractorPartialState {
    data class Success(
        val verifierName: String?,
        val verifierIsTrusted: Boolean,
        val requestDocuments: List<RequestDocumentItemUi>,
    ) : PresentationRequestInteractorPartialState()

    data class NoData(
        val verifierName: String?,
        val verifierIsTrusted: Boolean,
    ) : PresentationRequestInteractorPartialState()

    data class Failure(
        val error: String,
        val errorType: ErrorType = ErrorType.GENERIC,
    ) : PresentationRequestInteractorPartialState()
    data object Disconnect : PresentationRequestInteractorPartialState()
}

interface PresentationRequestInteractor {
    fun getRequestDocuments(): Flow<PresentationRequestInteractorPartialState>
    fun stopPresentation()
    fun updateRequestedDocuments(items: List<RequestDocumentItemUi>)
    fun setConfig(config: RequestUriConfig)
    fun startDCAPIPresentation(context: Context)
    fun shouldUseAppAuthenticationBeforePresentation(): Boolean
}

class PresentationRequestInteractorImpl(
    private val resourceProvider: ResourceProvider,
    private val uuidProvider: UuidProvider,
    private val walletCorePresentationController: WalletCorePresentationController,
    private val walletCoreDocumentsController: WalletCoreDocumentsController,
    private val dcApiIntentHolder: DcApiIntentHolder,
    private val vaultKeyProvider: VaultKeyProvider,
    private val walletCoreConfig: WalletCoreConfig,
) : PresentationRequestInteractor {

    private val genericErrorMsg
        get() = resourceProvider.genericErrorMessage()

    override fun setConfig(config: RequestUriConfig) {
        val domainConfig = config.toDomainConfig()

        val finalConfig = if (config.presentationMode is DcApiPresentationMode) {
            val intent = dcApiIntentHolder.retrieveIntent()
            DcApiPresentationControllerConfig("", intent)
        } else {
            domainConfig
        }

        walletCorePresentationController.setConfig(finalConfig)
    }

    override fun startDCAPIPresentation(context: Context) {
        val intent = dcApiIntentHolder.retrieveIntent()
        intent?.let {
            walletCorePresentationController.startDCAPIPresentation(it)
        }
    }

    override fun getRequestDocuments(): Flow<PresentationRequestInteractorPartialState> =
        walletCorePresentationController.events.mapNotNull { response ->
            when (response) {
                is RequestReceived -> {
                    if (response.requestData.all { it.requestedItems.isEmpty() }) {
                        NoData(
                            verifierName = response.verifierName,
                            verifierIsTrusted = response.verifierIsTrusted,
                        )
                    } else {
                        calculateRequestDocuments(response)
                    }
                }

                is Error -> {
                    Failure(
                        error = response.error,
                        errorType = response.errorType,
                    )
                }

                is Disconnected -> {
                    Disconnect
                }

                else -> null
            }
        }.safeAsync {
            Failure(
                error = it.localizedMessage ?: genericErrorMsg,
                errorType = it.toErrorType(),
            )
        }

    private suspend fun calculateRequestDocuments(response: RequestReceived): PresentationRequestInteractorPartialState {
        val documentsDomain = extractDocuments(response)

        return if (documentsDomain.isNotEmpty()) {
            Success(
                verifierName = response.verifierName,
                verifierIsTrusted = response.verifierIsTrusted,
                requestDocuments = RequestTransformer.transformToUiItems(
                    documentsDomain = documentsDomain,
                    resourceProvider = resourceProvider,
                )
            )
        } else {
            NoData(
                verifierName = response.verifierName,
                verifierIsTrusted = response.verifierIsTrusted,
            )
        }
    }

    private suspend fun extractDocuments(response: RequestReceived): List<DocumentPayloadDomain> {
        val documentsDomain = RequestTransformer.transformToDomainItems(
            storageDocuments = walletCoreDocumentsController.getAllIssuedDocuments(),
            requestDocuments = response.requestData,
            resourceProvider = resourceProvider,
            uuidProvider = uuidProvider
        ).getOrThrow()
            .let { documents ->
                // The revoked-documents list lives in the vault-encrypted database. When the app
                // is resumed from background (e.g. via the OpenID4VP deeplink) the vault is locked,
                // so reading it here would fail. In that case we defer revocation enforcement to the
                // loading step, which runs after the user authenticates and the vault is unlocked.
                if (vaultKeyProvider.isUnlocked()) {
                    documents.filterNot {
                        walletCoreDocumentsController.isDocumentRevoked(it.docId)
                    }
                } else {
                    documents
                }
            }
        return documentsDomain
    }

    override fun stopPresentation() {
        walletCorePresentationController.stopPresentation()
    }

    override fun updateRequestedDocuments(items: List<RequestDocumentItemUi>) {
        val disclosedDocuments = RequestTransformer.createDisclosedDocuments(items)
        walletCorePresentationController.updateRequestedDocuments(disclosedDocuments.toMutableList())
    }

    override fun shouldUseAppAuthenticationBeforePresentation(): Boolean =
        !walletCoreConfig.userAuthenticationRequired
}
