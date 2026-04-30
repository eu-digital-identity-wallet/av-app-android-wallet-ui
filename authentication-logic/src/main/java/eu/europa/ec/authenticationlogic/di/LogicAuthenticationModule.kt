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

package eu.europa.ec.authenticationlogic.di

import eu.europa.ec.authenticationlogic.config.StorageConfig
import eu.europa.ec.authenticationlogic.config.StorageConfigImpl
import eu.europa.ec.authenticationlogic.controller.authentication.BiometricAuthenticationController
import eu.europa.ec.authenticationlogic.controller.authentication.BiometricAuthenticationControllerImpl
import eu.europa.ec.authenticationlogic.controller.authentication.DeviceAuthenticationController
import eu.europa.ec.authenticationlogic.controller.authentication.DeviceAuthenticationControllerImpl
import eu.europa.ec.authenticationlogic.controller.storage.BiometryStorageController
import eu.europa.ec.authenticationlogic.controller.storage.BiometryStorageControllerImpl
import eu.europa.ec.authenticationlogic.controller.storage.PinStorageController
import eu.europa.ec.authenticationlogic.controller.storage.PinStorageControllerImpl
import eu.europa.ec.authenticationlogic.storage.PrefsBiometryStorageProvider
import eu.europa.ec.authenticationlogic.storage.PrefsPinStorageProvider
import eu.europa.ec.businesslogic.controller.crypto.CryptoController
import eu.europa.ec.businesslogic.controller.storage.PrefsController
import eu.europa.ec.businesslogic.provider.BootIdProvider
import eu.europa.ec.businesslogic.provider.ElapsedRealtimeClock
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import org.koin.core.annotation.ComponentScan
import org.koin.core.annotation.Factory
import org.koin.core.annotation.Module
import org.koin.core.annotation.Single

@Module
@ComponentScan("eu.europa.ec.authenticationlogic")
class LogicAuthenticationModule

@Single
fun provideStorageConfig(
    prefsController: PrefsController,
    clock: ElapsedRealtimeClock,
    bootIdProvider: BootIdProvider,
): StorageConfig = StorageConfigImpl(
    pinImpl = PrefsPinStorageProvider(prefsController, clock, bootIdProvider),
    biometryImpl = PrefsBiometryStorageProvider(prefsController)
)

@Factory
fun provideBiometricAuthenticationController(
    cryptoController: CryptoController,
    biometryStorageController: BiometryStorageController,
    resourceProvider: ResourceProvider
): BiometricAuthenticationController =
    BiometricAuthenticationControllerImpl(
        resourceProvider,
        cryptoController,
        biometryStorageController
    )

@Factory
fun provideDeviceAuthenticationController(
    resourceProvider: ResourceProvider,
    biometricAuthenticationController: BiometricAuthenticationController
): DeviceAuthenticationController =
    DeviceAuthenticationControllerImpl(
        resourceProvider,
        biometricAuthenticationController
    )

@Factory
fun providePinStorageController(
    storageConfig: StorageConfig,
): PinStorageController = PinStorageControllerImpl(storageConfig)

@Factory
fun provideBiometryStorageController(
    storageConfig: StorageConfig
): BiometryStorageController = BiometryStorageControllerImpl(storageConfig)