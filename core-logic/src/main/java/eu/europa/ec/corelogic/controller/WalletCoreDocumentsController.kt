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

import androidx.core.net.toUri
import eu.europa.ec.authenticationlogic.controller.authentication.DeviceAuthenticationResult
import eu.europa.ec.authenticationlogic.model.BiometricCrypto
import eu.europa.ec.businesslogic.extension.safeAsync
import eu.europa.ec.businesslogic.extension.toErrorType
import eu.europa.ec.businesslogic.model.ErrorType
import eu.europa.ec.corelogic.config.WalletCoreConfig
import eu.europa.ec.corelogic.extension.documentIdentifier
import eu.europa.ec.corelogic.extension.getLocalizedDisplayName
import eu.europa.ec.corelogic.model.DeferredDocumentDataDomain
import eu.europa.ec.corelogic.model.DocumentCategories
import eu.europa.ec.corelogic.model.DocumentIdentifier
import eu.europa.ec.corelogic.model.FormatType
import eu.europa.ec.corelogic.model.ScopedDocumentDomain
import eu.europa.ec.corelogic.model.toDocumentIdentifier
import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadata
import eu.europa.ec.eudi.openid4vci.MsoMdocCredential
import eu.europa.ec.eudi.openid4vci.SdJwtVcCredential
import eu.europa.ec.eudi.statium.Status
import eu.europa.ec.eudi.wallet.EudiWallet
import eu.europa.ec.eudi.wallet.document.CreateDocumentSettings
import eu.europa.ec.eudi.wallet.document.DeferredDocument
import eu.europa.ec.eudi.wallet.document.Document
import eu.europa.ec.eudi.wallet.document.DocumentExtensions.getDefaultCreateDocumentSettings
import eu.europa.ec.eudi.wallet.document.DocumentExtensions.getDefaultKeyUnlockData
import eu.europa.ec.eudi.wallet.document.DocumentId
import eu.europa.ec.eudi.wallet.document.IssuedDocument
import eu.europa.ec.eudi.wallet.document.format.MsoMdocFormat
import eu.europa.ec.eudi.wallet.document.format.SdJwtVcFormat
import eu.europa.ec.eudi.wallet.issue.openid4vci.DeferredIssueResult
import eu.europa.ec.eudi.wallet.issue.openid4vci.IssueEvent
import eu.europa.ec.eudi.wallet.issue.openid4vci.Offer
import eu.europa.ec.eudi.wallet.issue.openid4vci.OfferResult
import eu.europa.ec.eudi.wallet.issue.openid4vci.OpenId4VciManager
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.storagelogic.storage.DatabaseManager
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.ProducerScope
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.channels.trySendBlocking
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.URLDecoder
import java.util.Locale

enum class IssuanceMethod {
    OPENID4VCI
}

sealed class IssueDocumentPartialState {
    data class Success(val documentId: String) : IssueDocumentPartialState()
    data class DeferredSuccess(val deferredDocuments: Map<String, String>) :
        IssueDocumentPartialState()

    data class Failure(
        val errorMessage: String,
        val errorType: ErrorType = ErrorType.GENERIC,
    ) : IssueDocumentPartialState()
    data class UserAuthRequired(
        val crypto: BiometricCrypto,
        val resultHandler: DeviceAuthenticationResult,
    ) : IssueDocumentPartialState()
}

sealed class IssueDocumentsPartialState {
    data class Success(val documentIds: List<DocumentId>) : IssueDocumentsPartialState()
    data class DeferredSuccess(val deferredDocuments: Map<DocumentId, FormatType>) :
        IssueDocumentsPartialState()

    data class PartialSuccess(
        val documentIds: List<DocumentId>,
        val nonIssuedDocuments: Map<String, String>,
    ) : IssueDocumentsPartialState()

    data class Failure(
        val errorMessage: String,
        val errorType: ErrorType = ErrorType.GENERIC,
    ) : IssueDocumentsPartialState()
    data class UserAuthRequired(
        val crypto: BiometricCrypto,
        val resultHandler: DeviceAuthenticationResult,
    ) : IssueDocumentsPartialState()
}

sealed class DeleteDocumentPartialState {
    data object Success : DeleteDocumentPartialState()
    data class Failure(val errorMessage: String) : DeleteDocumentPartialState()
}

sealed class DeleteAllDocumentsPartialState {
    data object Success : DeleteAllDocumentsPartialState()
    data class Failure(val errorMessage: String) : DeleteAllDocumentsPartialState()
}

sealed class ResolveDocumentOfferPartialState {
    data class Success(val offer: Offer) : ResolveDocumentOfferPartialState()
    data class Failure(
        val errorMessage: String,
        val errorType: ErrorType = ErrorType.GENERIC,
    ) : ResolveDocumentOfferPartialState()
}

sealed class FetchScopedDocumentsPartialState {
    data class Success(val documents: List<ScopedDocumentDomain>) :
        FetchScopedDocumentsPartialState()

    data class Failure(
        val errorMessage: String,
        val errorType: ErrorType = ErrorType.GENERIC,
    ) : FetchScopedDocumentsPartialState()
}

sealed class IssueDeferredDocumentPartialState {
    data class Issued(
        val deferredDocumentData: DeferredDocumentDataDomain,
    ) : IssueDeferredDocumentPartialState()

    data class NotReady(
        val deferredDocumentData: DeferredDocumentDataDomain,
    ) : IssueDeferredDocumentPartialState()

    data class Failed(
        val documentId: DocumentId,
        val errorMessage: String,
        val errorType: ErrorType = ErrorType.GENERIC,
    ) : IssueDeferredDocumentPartialState()

    data class Expired(
        val documentId: DocumentId,
    ) : IssueDeferredDocumentPartialState()
}

/**
 * Controller for interacting with internal local storage of Core for CRUD operations on documents
 * */
interface WalletCoreDocumentsController {

    /**
     * @return All the documents from the Database.
     * */
    fun getAllDocuments(): List<Document>

    fun getAllIssuedDocuments(): List<IssuedDocument>

    fun getAllDocumentsByType(documentIdentifiers: List<DocumentIdentifier>): List<IssuedDocument>

    fun getDocumentById(documentId: DocumentId): Document?

    fun getMainPidDocument(): IssuedDocument?

    fun issueDocument(
        issuanceMethod: IssuanceMethod,
        configId: String,
        issuerId: String
    ): Flow<IssueDocumentPartialState>

    fun issueDocumentsByOffer(
        offer: Offer,
        txCode: String? = null,
    ): Flow<IssueDocumentsPartialState>

    fun deleteDocument(
        documentId: String,
    ): Flow<DeleteDocumentPartialState>

    fun deleteAllDocuments(): Flow<DeleteAllDocumentsPartialState>

    fun deleteAllAgeDocuments(): Flow<DeleteAllDocumentsPartialState>

    fun resolveDocumentOffer(offerUri: String): Flow<ResolveDocumentOfferPartialState>

    fun issueDeferredDocument(docId: DocumentId): Flow<IssueDeferredDocumentPartialState>

    fun resumeOpenId4VciWithAuthorization(uri: String)

    suspend fun getScopedDocuments(locale: Locale): FetchScopedDocumentsPartialState

    fun getAllDocumentCategories(): DocumentCategories

    suspend fun getRevokedDocumentIds(): List<String>

    suspend fun isDocumentRevoked(id: String): Boolean

    suspend fun resolveDocumentStatus(document: IssuedDocument): Result<Status>

    suspend fun isDocumentLowOnCredentials(document: IssuedDocument): Boolean

    fun hasIssuedDocuments(): Boolean
}

class WalletCoreDocumentsControllerImpl(
    private val resourceProvider: ResourceProvider,
    private val eudiWallet: EudiWallet,
    private val walletCoreConfig: WalletCoreConfig,
    private val databaseManager: DatabaseManager,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) : WalletCoreDocumentsController {

    private val genericErrorMessage
        get() = resourceProvider.genericErrorMessage()

    private val documentErrorMessage
        get() = resourceProvider.getString(R.string.issuance_generic_error)

    private val openId4VciManagers by lazy {
        walletCoreConfig.vciConfig.associate { config ->
            config.issuerUrl to eudiWallet.createOpenId4VciManager(config = config)
        }
    }

    override fun getAllDocuments(): List<Document> =
        eudiWallet.getDocuments { it is IssuedDocument || it is DeferredDocument }

    override fun getAllIssuedDocuments(): List<IssuedDocument> =
        eudiWallet.getDocuments().filterIsInstance<IssuedDocument>()

    override suspend fun getScopedDocuments(locale: Locale): FetchScopedDocumentsPartialState {
        return withContext(dispatcher) {
            runCatching {

                val metadata: Map<String, CredentialIssuerMetadata> =
                    openId4VciManagers.mapValues { (_, manager) ->
                        manager.getIssuerMetadata().getOrThrow()
                    }

                val documents: List<ScopedDocumentDomain> =
                    metadata.flatMap { (issuer, meta) ->
                        meta.credentialConfigurationsSupported.map { (id, config) ->

                            val name: String = config.credentialMetadata.getLocalizedDisplayName(
                                userLocale = locale,
                                fallback = id.value
                            )

                            val isPid = when (config) {
                                is MsoMdocCredential -> config.docType.toDocumentIdentifier() == DocumentIdentifier.MdocPid
                                is SdJwtVcCredential -> config.type.toDocumentIdentifier() == DocumentIdentifier.SdJwtPid
                                else -> false
                            }

                            val isAgeVerification: Boolean = when (config) {
                                is MsoMdocCredential -> config.docType.toDocumentIdentifier() == DocumentIdentifier.MdocEUDIAgeOver18 ||
                                        config.docType.toDocumentIdentifier() == DocumentIdentifier.AVAgeOver18

                                is SdJwtVcCredential -> config.type.toDocumentIdentifier() == DocumentIdentifier.AVAgeOver18
                                else -> false
                            }

                            val formatType = when (config) {
                                is MsoMdocCredential -> config.docType
                                is SdJwtVcCredential -> config.type
                                else -> null
                            }

                            ScopedDocumentDomain(
                                name = name,
                                configurationId = id.value,
                                credentialIssuerId = issuer,
                                formatType = formatType,
                                isPid = isPid,
                                isAgeVerification = isAgeVerification
                            )
                        }
                    }

                if (documents.isNotEmpty()) {
                    FetchScopedDocumentsPartialState.Success(documents = documents)
                } else {
                    FetchScopedDocumentsPartialState.Failure(errorMessage = genericErrorMessage)
                }
            }
        }.getOrElse {
            FetchScopedDocumentsPartialState.Failure(
                errorMessage = it.localizedMessage ?: genericErrorMessage,
                errorType = it.toErrorType(),
            )
        }
    }

    override fun getAllDocumentsByType(documentIdentifiers: List<DocumentIdentifier>): List<IssuedDocument> =
        getAllDocuments()
            .filterIsInstance<IssuedDocument>()
            .filter {
                when (it.format) {
                    is MsoMdocFormat -> documentIdentifiers.any { id ->
                        id.formatType == (it.format as MsoMdocFormat).docType
                    }

                    is SdJwtVcFormat -> documentIdentifiers.any { id ->
                        id.formatType == (it.format as SdJwtVcFormat).vct
                    }
                }
            }

    override fun getDocumentById(documentId: DocumentId): Document? {
        return eudiWallet.getDocumentById(documentId = documentId)
    }

    override fun getMainPidDocument(): IssuedDocument? =
        getAllDocumentsByType(
            documentIdentifiers = listOf(
                DocumentIdentifier.MdocPid,
                DocumentIdentifier.SdJwtPid
            )
        ).minByOrNull { it.createdAt }

    override fun issueDocument(
        issuanceMethod: IssuanceMethod,
        configId: String,
        issuerId: String
    ): Flow<IssueDocumentPartialState> = flow {
        when (issuanceMethod) {
            IssuanceMethod.OPENID4VCI -> {
                issueDocumentWithOpenId4VCI(configId, issuerId).collect { response ->
                    when (response) {
                        is IssueDocumentsPartialState.Failure -> emit(
                            IssueDocumentPartialState.Failure(
                                errorMessage = documentErrorMessage
                            )
                        )

                        is IssueDocumentsPartialState.Success -> emit(
                            IssueDocumentPartialState.Success(
                                response.documentIds.first()
                            )
                        )

                        is IssueDocumentsPartialState.UserAuthRequired -> emit(
                            IssueDocumentPartialState.UserAuthRequired(
                                crypto = response.crypto,
                                resultHandler = response.resultHandler
                            )
                        )

                        is IssueDocumentsPartialState.PartialSuccess -> emit(
                            IssueDocumentPartialState.Success(
                                response.documentIds.first()
                            )
                        )

                        is IssueDocumentsPartialState.DeferredSuccess -> emit(
                            IssueDocumentPartialState.DeferredSuccess(
                                response.deferredDocuments
                            )
                        )
                    }
                }
            }
        }
    }.safeAsync {
        IssueDocumentPartialState.Failure(
            errorMessage = documentErrorMessage,
            errorType = it.toErrorType(),
        )
    }

    override fun issueDocumentsByOffer(
        offer: Offer,
        txCode: String?,
    ): Flow<IssueDocumentsPartialState> =
        callbackFlow {

            val issuerId = offer
                .credentialOffer
                .credentialIssuerIdentifier
                .toString()

            val manager = openId4VciManagers[issuerId]
                ?: openId4VciManagers.values.firstOrNull()

            require(manager != null) { documentErrorMessage }

            manager.issueDocumentByOffer(
                offer = offer,
                onIssueEvent = issuanceCallback(),
                txCode = txCode,
            )
            awaitClose()
        }.safeAsync {
            IssueDocumentsPartialState.Failure(
                errorMessage = documentErrorMessage,
                errorType = it.toErrorType(),
            )
        }

    override fun deleteDocument(documentId: String): Flow<DeleteDocumentPartialState> = flow {
        eudiWallet.deleteDocumentById(documentId = documentId)
            .kotlinResult
            .onSuccess {
                databaseManager.revokedDocumentDao().delete(documentId)
                emit(DeleteDocumentPartialState.Success)
            }
            .onFailure {
                emit(
                    DeleteDocumentPartialState.Failure(
                        errorMessage = it.localizedMessage
                            ?: genericErrorMessage
                    )
                )
            }
    }.safeAsync {
        DeleteDocumentPartialState.Failure(
            errorMessage = it.localizedMessage ?: genericErrorMessage
        )
    }

    override fun deleteAllAgeDocuments() : Flow<DeleteAllDocumentsPartialState> = flow {
        val allDocuments = getAllDocuments()
        val ageDocumentIds = listOf(
            DocumentIdentifier.AVAgeOver18,
            DocumentIdentifier.MdocEUDIAgeOver18
        )
        val ageDocuments = allDocuments.filter { document ->
             ageDocumentIds.contains(document.toDocumentIdentifier())
        }

        var allDeleted = true
        var failureReason = ""

        ageDocuments.forEach { document ->
            deleteDocument(documentId = document.id).collect { deleteDocumentPartialState ->
                when (deleteDocumentPartialState) {
                    is DeleteDocumentPartialState.Failure -> {
                        allDeleted = false
                        failureReason = deleteDocumentPartialState.errorMessage
                    }
                    is DeleteDocumentPartialState.Success -> { /* continue */ }
                }
            }
        }

        val state = if (allDeleted) {
            DeleteAllDocumentsPartialState.Success
        } else {
            DeleteAllDocumentsPartialState.Failure(errorMessage = failureReason)
        }
        emit(state)
    }

    override fun deleteAllDocuments(): Flow<DeleteAllDocumentsPartialState> =
        flow {

            val allDocuments = getAllDocuments()
            val mainPidDocument = getMainPidDocument()

            mainPidDocument?.let { safeMainPidDocument ->

                val restOfDocuments = allDocuments.filterNot { doc ->
                    doc.id == safeMainPidDocument.id
                }

                var restOfAllDocsDeleted = true
                var restOfAllDocsDeletedFailureReason = ""

                restOfDocuments.forEach { document ->

                    deleteDocument(
                        documentId = document.id
                    ).collect { deleteDocumentPartialState ->
                        when (deleteDocumentPartialState) {
                            is DeleteDocumentPartialState.Failure -> {
                                restOfAllDocsDeleted = false
                                restOfAllDocsDeletedFailureReason =
                                    deleteDocumentPartialState.errorMessage
                            }

                            is DeleteDocumentPartialState.Success -> {}
                        }
                    }
                }

                if (restOfAllDocsDeleted) {
                    deleteDocument(
                        documentId = safeMainPidDocument.id
                    ).collect { deleteMainPidDocumentPartialState ->
                        when (deleteMainPidDocumentPartialState) {
                            is DeleteDocumentPartialState.Failure -> emit(
                                DeleteAllDocumentsPartialState.Failure(
                                    errorMessage = deleteMainPidDocumentPartialState.errorMessage
                                )
                            )

                            is DeleteDocumentPartialState.Success -> emit(
                                DeleteAllDocumentsPartialState.Success
                            )
                        }
                    }
                } else {
                    emit(DeleteAllDocumentsPartialState.Failure(errorMessage = restOfAllDocsDeletedFailureReason))
                }
            } ?: emit(
                DeleteAllDocumentsPartialState.Failure(
                    errorMessage = genericErrorMessage
                )
            )
        }.safeAsync {
            DeleteAllDocumentsPartialState.Failure(
                errorMessage = it.localizedMessage ?: genericErrorMessage
            )
        }

    override fun resolveDocumentOffer(offerUri: String): Flow<ResolveDocumentOfferPartialState> =
        callbackFlow {

            val issuerId = extractCredentialIssuerFromOfferUri(offerUri).getOrNull()

            val manager = issuerId?.let { id -> openId4VciManagers[id] }
                ?: openId4VciManagers.values.firstOrNull()

            require(manager != null) { genericErrorMessage }

            manager.resolveDocumentOffer(offerUri) { result ->
                when (result) {
                    is OfferResult.Failure -> {
                        trySendBlocking(
                            ResolveDocumentOfferPartialState.Failure(
                                errorMessage = result.cause.localizedMessage ?: genericErrorMessage,
                                errorType = result.cause.toErrorType(),
                            )
                        )
                    }

                    is OfferResult.Success -> {
                        trySendBlocking(
                            ResolveDocumentOfferPartialState.Success(
                                offer = result.offer
                            )
                        )
                    }
                }
            }
            awaitClose()
        }.safeAsync {
            ResolveDocumentOfferPartialState.Failure(
                errorMessage = it.localizedMessage ?: genericErrorMessage,
                errorType = it.toErrorType(),
            )
        }

    override fun issueDeferredDocument(docId: DocumentId): Flow<IssueDeferredDocumentPartialState> =
        callbackFlow {
            (getDocumentById(docId) as? DeferredDocument)?.let { deferredDoc ->

                val manager = deferredDoc.issuerMetadata?.credentialIssuerIdentifier
                    ?.let(openId4VciManagers::get)
                    ?: openId4VciManagers.values.firstOrNull()

                require(manager != null) { documentErrorMessage }

                manager.issueDeferredDocument(
                    deferredDocument = deferredDoc,
                    executor = null,
                    onIssueResult = { deferredIssuanceResult ->
                        when (deferredIssuanceResult) {
                            is DeferredIssueResult.DocumentFailed -> {
                                trySendBlocking(
                                    IssueDeferredDocumentPartialState.Failed(
                                        documentId = deferredIssuanceResult.documentId,
                                        errorMessage = deferredIssuanceResult.cause.localizedMessage
                                            ?: documentErrorMessage,
                                        errorType = deferredIssuanceResult.cause.toErrorType(),
                                    )
                                )
                            }

                            is DeferredIssueResult.DocumentIssued -> {
                                trySendBlocking(
                                    IssueDeferredDocumentPartialState.Issued(
                                        DeferredDocumentDataDomain(
                                            documentId = deferredIssuanceResult.documentId,
                                            formatType = deferredIssuanceResult.docType,
                                            docName = deferredIssuanceResult.name
                                        )
                                    )
                                )
                            }

                            is DeferredIssueResult.DocumentNotReady -> {
                                trySendBlocking(
                                    IssueDeferredDocumentPartialState.NotReady(
                                        DeferredDocumentDataDomain(
                                            documentId = deferredIssuanceResult.documentId,
                                            formatType = deferredIssuanceResult.docType,
                                            docName = deferredIssuanceResult.name
                                        )
                                    )
                                )
                            }

                            is DeferredIssueResult.DocumentExpired -> {
                                trySendBlocking(
                                    IssueDeferredDocumentPartialState.Expired(
                                        documentId = deferredIssuanceResult.documentId
                                    )
                                )
                            }
                        }
                    }
                )
            } ?: trySendBlocking(
                IssueDeferredDocumentPartialState.Failed(
                    documentId = docId,
                    errorMessage = documentErrorMessage
                )
            )

            awaitClose()
        }.safeAsync {
            IssueDeferredDocumentPartialState.Failed(
                documentId = docId,
                errorMessage = it.localizedMessage ?: genericErrorMessage,
                errorType = it.toErrorType(),
            )
        }

    override fun resumeOpenId4VciWithAuthorization(uri: String) {
        for (manager in openId4VciManagers.values) {
            try {
                manager.resumeWithAuthorization(uri)
                break
            } catch (_: Exception) {
            }
        }
    }

    override fun getAllDocumentCategories(): DocumentCategories {
        return walletCoreConfig.documentCategories
    }

    override fun hasIssuedDocuments(): Boolean = eudiWallet.getDocuments{ it is IssuedDocument}.isNotEmpty()

    override suspend fun isDocumentLowOnCredentials(document: IssuedDocument): Boolean {
        val documentRemainingCredentials = document.credentialsCount()

        return document.credentialPolicy == CreateDocumentSettings.CredentialPolicy.OneTimeUse
                && documentRemainingCredentials <= 1
    }

    override suspend fun getRevokedDocumentIds(): List<String> =
        databaseManager.revokedDocumentDao().retrieveAll().map { it.identifier }

    override suspend fun isDocumentRevoked(id: String): Boolean =
        databaseManager.revokedDocumentDao().retrieve(id) != null

    override suspend fun resolveDocumentStatus(document: IssuedDocument): Result<Status> =
        eudiWallet.resolveStatus(document)

    private fun issueDocumentWithOpenId4VCI(
        configId: String,
        issuerId: String
    ): Flow<IssueDocumentsPartialState> =
        callbackFlow {

            val manager = openId4VciManagers[issuerId]
            require(manager != null) { documentErrorMessage }

            manager.issueDocumentByConfigurationIdentifiers(
                credentialConfigurationIds = listOf(configId),
                onIssueEvent = issuanceCallback()
            )

            awaitClose()

        }.safeAsync {
            IssueDocumentsPartialState.Failure(
                errorMessage = documentErrorMessage,
                errorType = it.toErrorType(),
            )
        }

    private fun ProducerScope<IssueDocumentsPartialState>.issuanceCallback(): OpenId4VciManager.OnIssueEvent {

        var totalDocumentsToBeIssued = 0
        val nonIssuedDocuments: MutableMap<FormatType, String> = mutableMapOf()
        val deferredDocuments: MutableMap<DocumentId, FormatType> = mutableMapOf()
        val issuedDocuments: MutableMap<DocumentId, FormatType> = mutableMapOf()

        val listener = OpenId4VciManager.OnIssueEvent { event ->
            when (event) {
                is IssueEvent.DocumentFailed -> {
                    nonIssuedDocuments[event.docType] = event.name
                }

                is IssueEvent.DocumentRequiresCreateSettings -> {
                    launch {
                        val offeredDocIdentifier = event.offeredDocument.documentIdentifier

                        val documentIssuanceRule = walletCoreConfig
                            .documentIssuanceConfig
                            .getRuleForDocument(documentIdentifier = offeredDocIdentifier)

                        event.resume(
                            eudiWallet.getDefaultCreateDocumentSettings(
                                offeredDocument = event.offeredDocument,
                                credentialPolicy = documentIssuanceRule.policy,
                                numberOfCredentials = documentIssuanceRule.numberOfCredentials,
                            )
                        )
                    }
                }

                is IssueEvent.DocumentRequiresUserAuth -> {
                    launch {
                        val keyUnlockDataMap =
                            event.keysRequireAuth.mapValues { (keyAlias, secureArea) ->
                                getDefaultKeyUnlockData(secureArea, keyAlias)
                            }

                        val keyUnlockData =
                            keyUnlockDataMap.values.first() //TODO: Revisit this once Core adds support.

                        val cryptoObject = keyUnlockData?.getCryptoObjectForSigning()

                        trySendBlocking(
                            IssueDocumentsPartialState.UserAuthRequired(
                                crypto = BiometricCrypto(cryptoObject),
                                resultHandler = DeviceAuthenticationResult(
                                    onAuthenticationSuccess = { event.resume(keyUnlockDataMap) },
                                    onAuthenticationError = { event.cancel(null) }
                                )
                            )
                        )
                    }
                }

                is IssueEvent.Failure -> {
                    trySendBlocking(
                        IssueDocumentsPartialState.Failure(
                            errorMessage = documentErrorMessage,
                            errorType = event.cause.toErrorType(),
                        )
                    )
                }

                is IssueEvent.Finished -> {

                    if (deferredDocuments.isNotEmpty()) {
                        trySendBlocking(IssueDocumentsPartialState.DeferredSuccess(deferredDocuments))
                        return@OnIssueEvent
                    }

                    if (event.issuedDocuments.isEmpty()) {
                        trySendBlocking(
                            IssueDocumentsPartialState.Failure(
                                errorMessage = documentErrorMessage
                            )
                        )
                        return@OnIssueEvent
                    }

                    if (event.issuedDocuments.size == totalDocumentsToBeIssued) {
                        trySendBlocking(
                            IssueDocumentsPartialState.Success(
                                documentIds = event.issuedDocuments
                            )
                        )
                        return@OnIssueEvent
                    }

                    trySendBlocking(
                        IssueDocumentsPartialState.PartialSuccess(
                            documentIds = event.issuedDocuments,
                            nonIssuedDocuments = nonIssuedDocuments
                        )
                    )
                }

                is IssueEvent.DocumentIssued -> {
                    issuedDocuments[event.documentId] = event.docType
                }

                is IssueEvent.Started -> {
                    totalDocumentsToBeIssued = event.total
                }

                is IssueEvent.DocumentDeferred -> {
                    deferredDocuments[event.documentId] = event.docType
                }
            }
        }

        return listener
    }

    private fun extractCredentialIssuerFromOfferUri(offerUri: String): Result<String> =
        runCatching {
            val credentialOffer = offerUri.toUri().getQueryParameter("credential_offer")
                ?: error("Missing 'credential_offer' query parameter in offer URI")
            val decoded = URLDecoder.decode(credentialOffer, "UTF-8")
            val json = JSONObject(decoded)
            json.getString("credential_issuer")
    }
}
