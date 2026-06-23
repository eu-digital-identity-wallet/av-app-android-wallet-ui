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

package eu.europa.ec.commonfeature.di

import eu.europa.ec.authenticationlogic.controller.authentication.BiometricAuthenticationController
import eu.europa.ec.authenticationlogic.controller.authentication.DeviceAuthenticationController
import eu.europa.ec.authenticationlogic.controller.storage.BiometryStorageController
import eu.europa.ec.authenticationlogic.controller.storage.PinStorageController
import eu.europa.ec.businesslogic.validator.FormValidator
import eu.europa.ec.commonfeature.interactor.BiometricInteractor
import eu.europa.ec.commonfeature.interactor.BiometricInteractorImpl
import eu.europa.ec.commonfeature.interactor.DeviceAuthenticationInteractor
import eu.europa.ec.commonfeature.interactor.DeviceAuthenticationInteractorImpl
import eu.europa.ec.commonfeature.interactor.QuickPinInteractor
import eu.europa.ec.commonfeature.interactor.QuickPinInteractorImpl
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import org.koin.core.annotation.ComponentScan
import org.koin.core.annotation.Factory
import org.koin.core.annotation.Module
import org.koin.core.annotation.Scope
import org.koin.mp.KoinPlatform

const val CREDENTIAL_OFFER_ISSUANCE_SCOPE_ID = "credential_offer_scope_id"

@Module
@ComponentScan("eu.europa.ec.commonfeature")
class FeatureCommonModule

@Factory
fun provideQuickPinInteractor(
    formValidator: FormValidator,
    pinStorageController: PinStorageController,
    resourceProvider: ResourceProvider
): QuickPinInteractor {
    return QuickPinInteractorImpl(formValidator, pinStorageController, resourceProvider)
}

@Factory
fun provideBiometricInteractor(
    biometryStorageController: BiometryStorageController,
    biometricAuthenticationController: BiometricAuthenticationController,
    resourceProvider: ResourceProvider,
    quickPinInteractor: QuickPinInteractor
): BiometricInteractor {
    return BiometricInteractorImpl(
        biometryStorageController,
        biometricAuthenticationController,
        resourceProvider,
        quickPinInteractor
    )
}

@Factory
fun provideDeviceAuthenticationInteractor(
    deviceAuthenticationController: DeviceAuthenticationController,
): DeviceAuthenticationInteractor {
    return DeviceAuthenticationInteractorImpl(deviceAuthenticationController)
}

@Scope
class CredentialOfferIssuanceScope

fun getOrCreateCredentialOfferScope(): org.koin.core.scope.Scope =
    KoinPlatform.getKoin()
        .getOrCreateScope<CredentialOfferIssuanceScope>(CREDENTIAL_OFFER_ISSUANCE_SCOPE_ID)
