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

package eu.europa.ec.landingfeature.di

import eu.europa.ec.businesslogic.provider.UuidProvider
import eu.europa.ec.corelogic.controller.WalletCoreDocumentsController
import eu.europa.ec.landingfeature.interactor.LandingPageInteractor
import eu.europa.ec.landingfeature.interactor.LandingPageInteractorImpl
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import org.koin.core.annotation.ComponentScan
import org.koin.core.annotation.Factory
import org.koin.core.annotation.Module

@Module
@ComponentScan("eu.europa.ec.landingfeature")
class FeatureLandingModule

@Factory
fun provideLandingPageInteractor(
    walletCoreDocumentsController: WalletCoreDocumentsController,
    resourceProvider: ResourceProvider,
    uuidProvider: UuidProvider,
): LandingPageInteractor =
    LandingPageInteractorImpl(
        walletCoreDocumentsController,
        resourceProvider,
        uuidProvider
    )

@Factory
fun provideSettingsInteractor(
    walletCoreDocumentsController: WalletCoreDocumentsController,
): eu.europa.ec.landingfeature.interactor.SettingsInteractor =
    eu.europa.ec.landingfeature.interactor.SettingsInteractorImpl(walletCoreDocumentsController)