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

package eu.europa.ec.corelogic.di

import android.content.Context
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.businesslogic.provider.UuidProvider
import eu.europa.ec.corelogic.config.WalletCoreConfig
import eu.europa.ec.corelogic.config.WalletCoreConfigImpl
import eu.europa.ec.corelogic.controller.PassportScanningDocumentsController
import eu.europa.ec.corelogic.controller.PassportScanningDocumentsControllerImpl
import eu.europa.ec.corelogic.controller.WalletCoreDocumentsController
import eu.europa.ec.corelogic.controller.WalletCoreDocumentsControllerImpl
import eu.europa.ec.corelogic.controller.WalletCoreLogController
import eu.europa.ec.corelogic.controller.WalletCoreLogControllerImpl
import eu.europa.ec.corelogic.controller.WalletCoreTransactionLogController
import eu.europa.ec.corelogic.controller.WalletCoreTransactionLogControllerImpl
import eu.europa.ec.corelogic.provider.WalletCoreAttestationProvider
import eu.europa.ec.corelogic.provider.WalletCoreAttestationProviderImpl
import eu.europa.ec.eudi.wallet.EudiWallet
import eu.europa.ec.networklogic.repository.WalletAttestationRepository
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.storagelogic.dao.RevokedDocumentDao
import eu.europa.ec.storagelogic.dao.TransactionLogDao
import io.ktor.client.HttpClient
import org.koin.core.annotation.ComponentScan
import org.koin.core.annotation.Factory
import org.koin.core.annotation.Module
import org.koin.core.annotation.Scope
import org.koin.core.annotation.Single
import org.koin.mp.KoinPlatform

const val PRESENTATION_SCOPE_ID = "presentation_scope_id"

@Module
@ComponentScan("eu.europa.ec.corelogic")
class LogicCoreModule

@Single
fun provideEudiWallet(
    context: Context,
    walletCoreConfig: WalletCoreConfig,
    walletCoreLogController: WalletCoreLogController,
    walletCoreTransactionLogController: WalletCoreTransactionLogController,
    walletCoreAttestationProvider: WalletCoreAttestationProvider,
    httpClient: HttpClient
): EudiWallet = EudiWallet(
    context = context,
    config = walletCoreConfig.config,
    walletProvider = walletCoreAttestationProvider
) {
    withLogger(walletCoreLogController)
    withTransactionLogger(walletCoreTransactionLogController)
    withKtorHttpClientFactory { httpClient }
}

@Single
fun provideWalletCoreConfig(
    context: Context,
): WalletCoreConfig = WalletCoreConfigImpl(context)

@Single
fun provideWalletCoreLogController(logController: LogController): WalletCoreLogController =
    WalletCoreLogControllerImpl(logController)

@Single
fun provideWalletCoreTransactionLogController(
    transactionLogDao: TransactionLogDao,
    uuidProvider: UuidProvider
): WalletCoreTransactionLogController = WalletCoreTransactionLogControllerImpl(
    transactionLogDao = transactionLogDao,
    uuidProvider = uuidProvider
)

@Single
fun provideWalletCoreAttestationProvider(
    walletAttestationRepository: WalletAttestationRepository,
    walletCoreConfig: WalletCoreConfig
): WalletCoreAttestationProvider =
    WalletCoreAttestationProviderImpl(
        walletCoreConfig = walletCoreConfig,
        walletAttestationRepository = walletAttestationRepository
    )

@Factory
fun provideWalletCoreDocumentsController(
    resourceProvider: ResourceProvider,
    eudiWallet: EudiWallet,
    walletCoreConfig: WalletCoreConfig,
    revokedDocumentDao: RevokedDocumentDao,
): WalletCoreDocumentsController =
    WalletCoreDocumentsControllerImpl(
        resourceProvider,
        eudiWallet,
        walletCoreConfig,
        revokedDocumentDao
    )

@Factory
fun providePassportScanningDocumentsController(
    walletCoreDocumentsController: WalletCoreDocumentsController,
    resourceProvider: ResourceProvider,
    eudiWallet: EudiWallet,
    walletCoreConfig: WalletCoreConfig,
): PassportScanningDocumentsController =
    PassportScanningDocumentsControllerImpl(
        walletCoreDocumentsController,
        resourceProvider,
        eudiWallet,
        walletCoreConfig
    )

/**
 * Koin scope that lives for all the document presentation flow. It is manually handled from the
 * ViewModels that start and participate on the presentation process
 * */
@Scope
class WalletPresentationScope

/**
 * Get Koin scope that lives during document presentation flow
 * */
fun getOrCreatePresentationScope(): org.koin.core.scope.Scope =
    KoinPlatform.getKoin().getOrCreateScope<WalletPresentationScope>(PRESENTATION_SCOPE_ID)