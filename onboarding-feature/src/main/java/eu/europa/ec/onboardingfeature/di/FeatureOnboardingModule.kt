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

@file:OptIn(ExperimentalTime::class)

package eu.europa.ec.onboardingfeature.di

import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.commonfeature.interactor.DeviceAuthenticationInteractor
import eu.europa.ec.corelogic.config.WalletCoreConfig
import eu.europa.ec.corelogic.controller.PassportScanningDocumentsController
import eu.europa.ec.corelogic.controller.WalletCoreDocumentsController
import eu.europa.ec.onboardingfeature.controller.FaceMatchController
import eu.europa.ec.onboardingfeature.controller.FaceMatchControllerImpl
import eu.europa.ec.onboardingfeature.interactor.ConsentInteractor
import eu.europa.ec.onboardingfeature.interactor.ConsentInteractorImpl
import eu.europa.ec.onboardingfeature.interactor.DocumentIdentificationInteractor
import eu.europa.ec.onboardingfeature.interactor.DocumentIdentificationInteractorImpl
import eu.europa.ec.onboardingfeature.interactor.EnrollmentInteractor
import eu.europa.ec.onboardingfeature.interactor.EnrollmentInteractorImpl
import eu.europa.ec.onboardingfeature.interactor.PassportCredentialIssuanceInteractor
import eu.europa.ec.onboardingfeature.interactor.PassportCredentialIssuanceInteractorImpl
import eu.europa.ec.onboardingfeature.interactor.PassportLiveVideoInteractor
import eu.europa.ec.onboardingfeature.interactor.PassportLiveVideoInteractorImpl
import eu.europa.ec.onboardingfeature.interactor.PassportScanIntroInteractor
import eu.europa.ec.onboardingfeature.interactor.PassportScanIntroInteractorImpl
import eu.europa.ec.onboardingfeature.session.PassportOnboardingSession
import eu.europa.ec.passportscanner.face.AVFaceMatchSDK
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.uilogic.serializer.UiSerializer
import org.koin.core.annotation.ComponentScan
import org.koin.core.annotation.Factory
import org.koin.core.annotation.Module
import org.koin.core.annotation.Single
import kotlin.time.ExperimentalTime

@Module
@ComponentScan("eu.europa.ec.onboardingfeature")
class FeatureOnboardingModule

@Single
fun providePassportOnboardingSession(): PassportOnboardingSession = PassportOnboardingSession()

@Factory
fun provideConsentInteractor(): ConsentInteractor = ConsentInteractorImpl()

@Factory
fun provideEnrollmentInteractor(
    walletCoreDocumentsController: WalletCoreDocumentsController,
    deviceAuthenticationInteractor: DeviceAuthenticationInteractor,
    resourceProvider: ResourceProvider,
    uiSerializer: UiSerializer,
    walletCoreConfig: WalletCoreConfig,
): EnrollmentInteractor = EnrollmentInteractorImpl(
    walletCoreDocumentsController,
    deviceAuthenticationInteractor,
    resourceProvider,
    uiSerializer,
    walletCoreConfig
)

@Single
fun provideFaceMatchController(
    walletCoreConfig: WalletCoreConfig,
    avFaceMatchSDK: AVFaceMatchSDK,
): FaceMatchController = FaceMatchControllerImpl(walletCoreConfig, avFaceMatchSDK)

@Factory
fun providePassportScanIntroInteractor(
    faceMatchController: FaceMatchController,
): PassportScanIntroInteractor = PassportScanIntroInteractorImpl(
    faceMatchController
)

@Factory
fun providePassportLiveVideoInteractor(
    faceMatchController: FaceMatchController,
    resourceProvider: ResourceProvider,
    logController: LogController,
): PassportLiveVideoInteractor = PassportLiveVideoInteractorImpl(
    faceMatchController,
    resourceProvider,
    logController
)

@Factory
fun provideDocumentIdentificationInteractor(
    resourceProvider: ResourceProvider,
    logController: LogController,
): DocumentIdentificationInteractor = DocumentIdentificationInteractorImpl(
    resourceProvider,
    logController
)

@Factory
fun providePassportCredentialIssuanceInteractor(
    passportScanningDocumentsController: PassportScanningDocumentsController,
    deviceAuthenticationInteractor: DeviceAuthenticationInteractor,
    resourceProvider: ResourceProvider,
    uiSerializer: UiSerializer,
): PassportCredentialIssuanceInteractor = PassportCredentialIssuanceInteractorImpl(
    passportScanningDocumentsController,
    deviceAuthenticationInteractor,
    resourceProvider,
    uiSerializer
)
