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

import android.content.Intent
import eu.europa.ec.authenticationlogic.model.BiometricCrypto
import eu.europa.ec.businesslogic.extension.addOrReplace
import eu.europa.ec.businesslogic.extension.safeAsync
import eu.europa.ec.businesslogic.extension.toErrorType
import eu.europa.ec.businesslogic.extension.toUri
import eu.europa.ec.businesslogic.model.ErrorType
import eu.europa.ec.corelogic.di.WalletPresentationScope
import eu.europa.ec.corelogic.model.AuthenticationData
import eu.europa.ec.corelogic.util.EudiWalletListenerWrapper
import eu.europa.ec.eudi.iso18013.transfer.response.DisclosedDocument
import eu.europa.ec.eudi.iso18013.transfer.response.DisclosedDocuments
import eu.europa.ec.eudi.iso18013.transfer.response.RequestProcessor
import eu.europa.ec.eudi.iso18013.transfer.response.RequestedDocument
import eu.europa.ec.eudi.iso18013.transfer.toKotlinResult
import eu.europa.ec.eudi.wallet.EudiWallet
import eu.europa.ec.eudi.wallet.document.DocumentExtensions.getDefaultKeyUnlockData
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.channels.trySendBlocking
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.mapNotNull
import kotlinx.coroutines.flow.merge
import kotlinx.coroutines.flow.shareIn
import kotlinx.coroutines.launch
import org.koin.core.annotation.Scope
import org.koin.core.annotation.Scoped
import java.net.URI

sealed class PresentationControllerConfig(val initiatorRoute: String) {
    data class OpenId4VP(val uri: String, val initiator: String) :
        PresentationControllerConfig(initiator)

    data class Ble(val initiator: String) : PresentationControllerConfig(initiator)
    data class DcApi(val initiator: String, val intent: Intent?) :
        PresentationControllerConfig(initiator)
}

sealed class TransferEventPartialState {
    data object Connected : TransferEventPartialState()
    data object Connecting : TransferEventPartialState()
    data object Disconnected : TransferEventPartialState()
    data class Error(
        val error: String,
        val errorType: ErrorType = ErrorType.GENERIC,
    ) : TransferEventPartialState()
    data class QrEngagementReady(val qrCode: String) : TransferEventPartialState()
    data class RequestReceived(
        val requestData: List<RequestedDocument>,
        val verifierName: String?,
        val verifierIsTrusted: Boolean,
    ) : TransferEventPartialState()

    data object ResponseSent : TransferEventPartialState()
    data class Redirect(val uri: URI) : TransferEventPartialState()
    data class IntentToSend(val intent: Intent) : TransferEventPartialState()
}

sealed class CheckKeyUnlockPartialState {
    data class Failure(
        val error: String,
        val errorType: ErrorType = ErrorType.GENERIC,
    ) : CheckKeyUnlockPartialState()
    data class UserAuthenticationRequired(
        val authenticationData: List<AuthenticationData>,
    ) : CheckKeyUnlockPartialState()

    data object RequestIsReadyToBeSent : CheckKeyUnlockPartialState()
}

sealed class SendRequestedDocumentsPartialState {
    data class Failure(
        val error: String,
        val errorType: ErrorType = ErrorType.GENERIC,
    ) : SendRequestedDocumentsPartialState()
    data object RequestSent : SendRequestedDocumentsPartialState()
}

sealed class ResponseReceivedPartialState {
    data object Success : ResponseReceivedPartialState()
    data class Redirect(val uri: URI) : ResponseReceivedPartialState()
    data class Failure(
        val error: String,
        val errorType: ErrorType = ErrorType.GENERIC,
    ) : ResponseReceivedPartialState()
    data class IntentToSend(val intent: Intent) : ResponseReceivedPartialState()
}

sealed class WalletCorePartialState {
    data class UserAuthenticationRequired(
        val authenticationData: List<AuthenticationData>,
    ) : WalletCorePartialState()

    data class Failure(
        val error: String,
        val errorType: ErrorType = ErrorType.GENERIC,
    ) : WalletCorePartialState()
    data object Success : WalletCorePartialState()
    data class Redirect(val uri: URI) : WalletCorePartialState()
    data object RequestIsReadyToBeSent : WalletCorePartialState()
    data class IntentToSend(val intent: Intent) : WalletCorePartialState()
}

/**
 * Common scoped interactor that has all the complexity and required interaction with the EudiWallet Core.
 * */
interface WalletCorePresentationController {
    /**
     * On initialization it adds the core listener and remove it when scope is canceled.
     * When the scope is canceled so does the presentation
     *
     * @return Hot Flow that emits the Core's status callback.
     * */
    val events: SharedFlow<TransferEventPartialState>

    /**
     * User selection data for request step
     * */
    val disclosedDocuments: MutableList<DisclosedDocument>?

    /**
     * Verifier name so it can be retrieve across screens
     * */
    val verifierName: String?

    val verifierIsTrusted: Boolean?

    /**
     * Who started the presentation
     * */
    val initiatorRoute: String

    val redirectUri: URI?

    /**
     * Set [PresentationControllerConfig]
     * */
    fun setConfig(config: PresentationControllerConfig)

    /**
     * Terminates the presentation and kills the coroutine scope that [events] live in
     * */
    fun stopPresentation()

    /**
     * Starts QR engagement. This will trigger [events] emission.
     *
     * [TransferEventPartialState.QrEngagementReady] -> QR String to show QR
     *
     * [TransferEventPartialState.Connecting] -> Connecting
     *
     * [TransferEventPartialState.Connected] -> Connected. We can proceed to the next screen
     * */
    fun startQrEngagement()

    /**
     * Transform UI models to Domain and create -> sent the request.
     *
     * @return Flow that emits the creation state. On Success send the request.
     * The response of that request is emitted through [events]
     *  */
    fun checkForKeyUnlock(): Flow<CheckKeyUnlockPartialState>

    fun sendRequestedDocuments(): SendRequestedDocumentsPartialState

    /**
     * Updates the UI model
     * @param disclosedDocuments User updated data through UI Events
     * */
    fun updateRequestedDocuments(disclosedDocuments: MutableList<DisclosedDocument>?)

    /**
     * @return flow that maps the state from [events] emission to what we consider as success state
     * */
    fun mappedCallbackStateFlow(): Flow<ResponseReceivedPartialState>

    /**
     * The main observation point for collecting state for the Request flow.
     * Exposes a single flow for two operations([checkForKeyUnlock] - [mappedCallbackStateFlow])
     * and a single state
     * @return flow that emits the create, sent, receive states
     * */
    fun observeSentDocumentsRequest(): Flow<WalletCorePartialState>

    /**
     * Starts DCAPI presentation flow with the provided intent
     * @param intent The DCAPI intent from the credential request
     * */
    fun startDCAPIPresentation(intent: Intent)
}

@Scope(WalletPresentationScope::class)
@Scoped
class WalletCorePresentationControllerImpl(
    private val eudiWallet: EudiWallet,
    private val resourceProvider: ResourceProvider,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) : WalletCorePresentationController {

    private val genericErrorMessage = resourceProvider.genericErrorMessage()

    private val coroutineScope = CoroutineScope(dispatcher + SupervisorJob())

    private lateinit var _config: PresentationControllerConfig

    override var disclosedDocuments: MutableList<DisclosedDocument>? = null

    private var processedRequest: RequestProcessor.ProcessedRequest.Success? = null

    override var verifierName: String? = null

    override var verifierIsTrusted: Boolean? = null

    override val initiatorRoute: String
        get() {
            val config = requireInit { _config }
            return config.initiatorRoute
        }

    override var redirectUri: URI? = null

    override fun setConfig(config: PresentationControllerConfig) {
        _config = config
    }

    override val events: SharedFlow<TransferEventPartialState> = callbackFlow {
        val eventListenerWrapper = EudiWalletListenerWrapper(
            onQrEngagementReady = { qrCode ->
                trySendBlocking(
                    TransferEventPartialState.QrEngagementReady(qrCode = qrCode)
                )
            },
            onConnected = {
                trySendBlocking(
                    TransferEventPartialState.Connected
                )
            },
            onConnecting = {
                trySendBlocking(
                    TransferEventPartialState.Connecting
                )
            },
            onDisconnected = {
                trySendBlocking(
                    TransferEventPartialState.Disconnected
                )
            },
            onError = { throwable ->
                trySendBlocking(
                    TransferEventPartialState.Error(
                        error = throwable.localizedMessage?.ifEmpty { genericErrorMessage }
                            ?: genericErrorMessage,
                        errorType = throwable.toErrorType(),
                    )
                )
            },
            onRequestReceived = { requestedDocumentData ->
                trySendBlocking(
                    requestedDocumentData.getOrNull()?.let { requestedDocuments ->

                    processedRequest = requestedDocuments

                        verifierName = requestedDocuments.requestedDocuments
                            .firstOrNull()?.readerAuth?.readerCommonName

                        val isTrusted = requestedDocuments.requestedDocuments
                            .firstOrNull()?.readerAuth?.isVerified == true
                        verifierIsTrusted = isTrusted

                        // Intentional: an unverified verifier (isTrusted == false) is not
                        // blocked. The trust status is surfaced as a UI badge on the
                        // presentation request screen so the user can make an informed choice.
                        // This wallet issues only age-over-X attestations; blocking unverified
                        // RPs would prevent use with parties that lack a formal mDL certificate
                        // but still need to verify age.
                        TransferEventPartialState.RequestReceived(
                            requestData = requestedDocuments.requestedDocuments,
                            verifierName = verifierName,
                            verifierIsTrusted = isTrusted
                        )
                    } ?: TransferEventPartialState.Error(error = genericErrorMessage)
                )
            },
            onResponseSent = {
                trySendBlocking(
                    TransferEventPartialState.ResponseSent
                )
            },
            onRedirect = { uri ->
                redirectUri = uri

                trySendBlocking(
                    TransferEventPartialState.Redirect(
                        uri = uri
                    )
                )
            },

            intentToSend = { intent ->
                trySendBlocking(
                    TransferEventPartialState.IntentToSend(intent)
                )
            }
        )

        addListener(eventListenerWrapper)
        awaitClose {
            removeListener(eventListenerWrapper)
            eudiWallet.stopProximityPresentation()
        }
    }.safeAsync {
        TransferEventPartialState.Error(
            error = it.localizedMessage ?: resourceProvider.genericErrorMessage(),
            errorType = it.toErrorType(),
        )
    }.shareIn(coroutineScope, SharingStarted.Lazily, 2)

    override fun startQrEngagement() {
        eudiWallet.startProximityPresentation()
    }

    override fun checkForKeyUnlock() = flow {
        disclosedDocuments?.let { documents ->

            val authenticationData = mutableListOf<AuthenticationData>()

            if (eudiWallet.config.userAuthenticationRequired) {

                val keyUnlockDataMap = documents.associateWith { disclosedDocument ->
                    eudiWallet.getDefaultKeyUnlockData(documentId = disclosedDocument.documentId)
                }

                for ((doc, kud) in keyUnlockDataMap) {

                    val cryptoObject = kud?.getCryptoObjectForSigning()

                    authenticationData.add(
                        AuthenticationData(
                            crypto = BiometricCrypto(cryptoObject),
                            onAuthenticationSuccess = {
                                disclosedDocuments?.addOrReplace(
                                    value = doc.copy(keyUnlockData = kud),
                                    replaceCondition = { disclosedDocument ->
                                        disclosedDocument.documentId == doc.documentId
                                    }
                                )
                            }
                        )
                    )
                }

                emit(
                    CheckKeyUnlockPartialState.UserAuthenticationRequired(
                        authenticationData
                    )
                )

            } else {
                emit(
                    CheckKeyUnlockPartialState.RequestIsReadyToBeSent
                )
            }
        }
    }.safeAsync {
        CheckKeyUnlockPartialState.Failure(
            error = it.localizedMessage ?: genericErrorMessage,
            errorType = it.toErrorType(),
        )
    }

    override fun sendRequestedDocuments(): SendRequestedDocumentsPartialState {
        return disclosedDocuments?.let { safeDisclosedDocuments ->

            var result: SendRequestedDocumentsPartialState =
                SendRequestedDocumentsPartialState.RequestSent

            processedRequest?.generateResponse(DisclosedDocuments(safeDisclosedDocuments.toList()))
                ?.toKotlinResult()
                ?.onFailure {
                    val errorMessage = it.localizedMessage ?: genericErrorMessage
                    result = SendRequestedDocumentsPartialState.Failure(
                        error = errorMessage
                    )
                }
                ?.onSuccess {
                    eudiWallet.sendResponse(it.response)
                    result = SendRequestedDocumentsPartialState.RequestSent
                }
            result
        } ?: SendRequestedDocumentsPartialState.Failure(
            error = genericErrorMessage
        )
    }

    override fun mappedCallbackStateFlow(): Flow<ResponseReceivedPartialState> {
        return events.mapNotNull { response ->
            when (response) {

                // Fix: Wallet core should return Success state here
                is TransferEventPartialState.Error -> {
                    if (response.error == "Peer disconnected without proper session termination") {
                        ResponseReceivedPartialState.Success
                    } else {
                        ResponseReceivedPartialState.Failure(
                            error = response.error,
                            errorType = response.errorType,
                        )
                    }
                }

                is TransferEventPartialState.Redirect -> {
                    ResponseReceivedPartialState.Redirect(uri = response.uri)
                }

                is TransferEventPartialState.Disconnected -> {
                    when {
                        events.replayCache.firstOrNull() is TransferEventPartialState.Redirect -> null
                        else -> ResponseReceivedPartialState.Success
                    }
                }

                is TransferEventPartialState.ResponseSent -> ResponseReceivedPartialState.Success

                is TransferEventPartialState.IntentToSend -> ResponseReceivedPartialState.IntentToSend(
                    response.intent
                )

                else -> null
            }
        }.safeAsync {
            ResponseReceivedPartialState.Failure(
                error = it.localizedMessage ?: genericErrorMessage,
                errorType = it.toErrorType(),
            )
        }
    }

    override fun observeSentDocumentsRequest(): Flow<WalletCorePartialState> =
        merge(checkForKeyUnlock(), mappedCallbackStateFlow()).mapNotNull {
            when (it) {
                is CheckKeyUnlockPartialState.Failure -> {
                    WalletCorePartialState.Failure(
                        error = it.error,
                        errorType = it.errorType,
                    )
                }

                is CheckKeyUnlockPartialState.UserAuthenticationRequired -> {
                    WalletCorePartialState.UserAuthenticationRequired(it.authenticationData)
                }

                is ResponseReceivedPartialState.Failure -> {
                    WalletCorePartialState.Failure(
                        error = it.error,
                        errorType = it.errorType,
                    )
                }

                is ResponseReceivedPartialState.Redirect -> {
                    WalletCorePartialState.Redirect(
                        uri = it.uri
                    )
                }

                is CheckKeyUnlockPartialState.RequestIsReadyToBeSent -> {
                    WalletCorePartialState.RequestIsReadyToBeSent
                }

                is ResponseReceivedPartialState.IntentToSend -> {
                    WalletCorePartialState.IntentToSend(it.intent)
                }

                else -> {
                    WalletCorePartialState.Success
                }
            }
        }.safeAsync {
            WalletCorePartialState.Failure(
                error = it.localizedMessage ?: genericErrorMessage,
                errorType = it.toErrorType(),
            )
        }

    override fun updateRequestedDocuments(disclosedDocuments: MutableList<DisclosedDocument>?) {
        this.disclosedDocuments = disclosedDocuments
    }

    override fun stopPresentation() {
        coroutineScope.cancel()
        CoroutineScope(dispatcher).launch {
            eudiWallet.stopProximityPresentation()
        }
    }

    override fun startDCAPIPresentation(intent: Intent) {
        eudiWallet.startDCAPIPresentation(intent)
    }

    private fun addListener(listener: EudiWalletListenerWrapper) {
        val config = requireInit { _config }
        eudiWallet.addTransferEventListener(listener)
        when (config) {
            is PresentationControllerConfig.OpenId4VP -> {
                eudiWallet.startRemotePresentation(config.uri.toUri())
            }

            is PresentationControllerConfig.DcApi -> {
                config.intent?.let {
                    eudiWallet.startDCAPIPresentation(it)
                }
            }

            else -> {
                // BLE or other modes don't require automatic start
            }
        }
    }

    private fun removeListener(listener: EudiWalletListenerWrapper) {
        requireInit { _config }
        eudiWallet.removeTransferEventListener(listener)
    }

    private fun <T> requireInit(block: () -> T): T {
        if (!::_config.isInitialized) {
            throw IllegalStateException("setConfig() must be called before using the WalletCorePresentationController")
        }
        return block()
    }
}