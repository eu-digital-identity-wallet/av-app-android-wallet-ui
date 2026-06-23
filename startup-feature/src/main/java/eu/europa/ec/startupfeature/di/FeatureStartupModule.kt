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

package eu.europa.ec.startupfeature.di

import eu.europa.ec.businesslogic.config.ConfigLogic
import eu.europa.ec.businesslogic.controller.crypto.KeystoreController
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.commonfeature.interactor.QuickPinInteractor
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.startupfeature.interactor.SplashInteractor
import eu.europa.ec.startupfeature.interactor.SplashInteractorImpl
import eu.europa.ec.uilogic.serializer.UiSerializer
import org.koin.core.annotation.ComponentScan
import org.koin.core.annotation.Factory
import org.koin.core.annotation.Module

@Module
@ComponentScan("eu.europa.ec.startupfeature")
class FeatureStartupModule

@Factory
fun provideSplashInteractor(
    quickPinInteractor: QuickPinInteractor,
    uiSerializer: UiSerializer,
    resourceProvider: ResourceProvider,
    keystoreController: KeystoreController,
    configLogic: ConfigLogic,
    logController: LogController,
): SplashInteractor = SplashInteractorImpl(
    quickPinInteractor,
    uiSerializer,
    resourceProvider,
    keystoreController,
    configLogic,
    logController,
)
