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

import eu.europa.ec.authenticationlogic.controller.authentication.DeviceAuthenticationResult
import eu.europa.ec.authenticationlogic.model.BiometricCrypto
import eu.europa.ec.businesslogic.extension.safeAsync
import eu.europa.ec.businesslogic.extension.toErrorType
import eu.europa.ec.corelogic.config.WalletCoreConfig
import eu.europa.ec.corelogic.extension.documentIdentifier
import eu.europa.ec.corelogic.extension.getLocalizedDisplayName
import eu.europa.ec.corelogic.model.DocumentIdentifier
import eu.europa.ec.corelogic.model.FormatType
import eu.europa.ec.corelogic.model.ScopedDocumentDomain
import eu.europa.ec.corelogic.model.toDocumentIdentifier
import eu.europa.ec.eudi.openid4vci.MsoMdocCredential
import eu.europa.ec.eudi.openid4vci.SdJwtVcCredential
import eu.europa.ec.eudi.wallet.EudiWallet
import eu.europa.ec.eudi.wallet.document.DocumentExtensions.getDefaultCreateDocumentSettings
import eu.europa.ec.eudi.wallet.document.DocumentExtensions.getDefaultKeyUnlockData
import eu.europa.ec.eudi.wallet.document.DocumentId
import eu.europa.ec.eudi.wallet.issue.openid4vci.IssueEvent
import eu.europa.ec.eudi.wallet.issue.openid4vci.OpenId4VciManager
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import java.util.Locale
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

/**
 * Controller for passport scanning document issuance operations.
 * Delegates standard document operations to WalletCoreDocumentsController while providing
 * specialized methods for issuing documents through the passport scanning issuer.
 */
interface PassportScanningDocumentsController : WalletCoreDocumentsController {

    /**
     * Get scoped documents from the passport scanning issuer
     * @param locale the locale to use for display names
     * @return FetchScopedDocumentsPartialState indicating success or failure
     */
    suspend fun getPassportScanningScopedDocuments(locale: Locale): FetchScopedDocumentsPartialState

    /**
     * Issue a document using the passport scanning issuer
     * @param issuanceMethod the issuance method to use
     * @param configId the configuration identifier for the document
     * @return Flow of IssueDocumentPartialState representing the issuance progress
     */
    fun issuePassportScanningDocument(
        issuanceMethod: IssuanceMethod,
        configId: String,
    ): Flow<IssueDocumentPartialState>

    /**
     * Resume OpenId4VCI authorization for passport scanning issuer
     * @param uri the authorization response URI
     */
    fun resumePassportScanningOpenId4VciWithAuthorization(uri: String)
}

class PassportScanningDocumentsControllerImpl(
    private val walletCoreDocumentsController: WalletCoreDocumentsController,
    private val resourceProvider: ResourceProvider,
    private val eudiWallet: EudiWallet,
    private val walletCoreConfig: WalletCoreConfig,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) : PassportScanningDocumentsController,
    WalletCoreDocumentsController by walletCoreDocumentsController {

    private val genericErrorMessage
        get() = resourceProvider.genericErrorMessage()

    private val documentErrorMessage
        get() = resourceProvider.getString(R.string.issuance_generic_error)

    private val passportScanningOpenId4VciManager by lazy {
        walletCoreConfig.passportScanningIssuerConfig?.let { config ->
            eudiWallet.createOpenId4VciManager(config)
        }
    }

    override suspend fun getPassportScanningScopedDocuments(locale: Locale): FetchScopedDocumentsPartialState {
        return withContext(dispatcher) {
            runCatching {
                val manager = passportScanningOpenId4VciManager
                    ?: return@runCatching FetchScopedDocumentsPartialState.Failure(
                        errorMessage = "Passport scanning issuer not configured"
                    )

                val metadata = manager.getIssuerMetadata().getOrThrow()

                val documents =
                    metadata.credentialConfigurationsSupported.map { (id, config) ->

                        val name = config.credentialMetadata.getLocalizedDisplayName(
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
                            credentialIssuerId = "passport_issuer",
                            formatType = formatType,
                            isPid = isPid,
                            isAgeVerification = isAgeVerification
                        )
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

    override fun issuePassportScanningDocument(
        issuanceMethod: IssuanceMethod,
        configId: String,
    ): Flow<IssueDocumentPartialState> = flow {
        when (issuanceMethod) {
            IssuanceMethod.OPENID4VCI -> {
                issuePassportScanningDocumentWithOpenId4VCI(configId).collect { response ->
                    when (response) {
                        is IssueDocumentsPartialState.Failure -> emit(
                            IssueDocumentPartialState.Failure(
                                errorMessage = documentErrorMessage,
                                errorType = response.errorType,
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

    private fun issuePassportScanningDocumentWithOpenId4VCI(configId: String): Flow<IssueDocumentsPartialState> =
        callbackFlow {
            val manager = passportScanningOpenId4VciManager
            if (manager == null) {
                trySendBlocking(
                    IssueDocumentsPartialState.Failure(
                        errorMessage = "Passport scanning issuer not configured"
                    )
                )
                awaitClose()
                return@callbackFlow
            }

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

                    if (nonIssuedDocuments.isEmpty() &&
                        (totalDocumentsToBeIssued == 0 || event.issuedDocuments.size == totalDocumentsToBeIssued)
                    ) {
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

    override fun resumePassportScanningOpenId4VciWithAuthorization(uri: String) {
        passportScanningOpenId4VciManager?.resumeWithAuthorization(uri)
    }
}
