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

package eu.europa.ec.businesslogic.di

import android.content.Context
import eu.europa.ec.businesslogic.config.ConfigLogic
import eu.europa.ec.businesslogic.config.ConfigLogicImpl
import eu.europa.ec.businesslogic.controller.crypto.CryptoController
import eu.europa.ec.businesslogic.controller.crypto.CryptoControllerImpl
import eu.europa.ec.businesslogic.controller.crypto.KeystoreController
import eu.europa.ec.businesslogic.controller.crypto.KeystoreControllerImpl
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.businesslogic.controller.log.LogControllerImpl
import eu.europa.ec.businesslogic.controller.storage.PrefKeys
import eu.europa.ec.businesslogic.controller.storage.PrefKeysImpl
import eu.europa.ec.businesslogic.controller.storage.PrefsController
import eu.europa.ec.businesslogic.controller.storage.PrefsControllerImpl
import android.os.SystemClock
import android.provider.Settings
import eu.europa.ec.businesslogic.provider.BootIdProvider
import eu.europa.ec.businesslogic.provider.ElapsedRealtimeClock
import eu.europa.ec.businesslogic.provider.UuidProvider
import eu.europa.ec.businesslogic.provider.UuidProviderImpl
import eu.europa.ec.businesslogic.validator.FilterValidator
import eu.europa.ec.businesslogic.validator.FilterValidatorImpl
import eu.europa.ec.businesslogic.validator.FormValidator
import eu.europa.ec.businesslogic.validator.FormValidatorImpl
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import org.koin.core.annotation.ComponentScan
import org.koin.core.annotation.Factory
import org.koin.core.annotation.Module
import org.koin.core.annotation.Single

@Module
@ComponentScan("eu.europa.ec.businesslogic")
class LogicBusinessModule

@Single
fun provideConfigLogic(context: Context): ConfigLogic = ConfigLogicImpl(context)

@Single
fun provideLogController(context: Context, configLogic: ConfigLogic): LogController =
    LogControllerImpl(context, configLogic)

@Single
fun providePrefsController(resourceProvider: ResourceProvider): PrefsController =
    PrefsControllerImpl(resourceProvider)

@Single
fun providePrefKeys(prefsController: PrefsController): PrefKeys =
    PrefKeysImpl(prefsController)

@Single
fun provideKeystoreController(
    prefKeys: PrefKeys,
    logController: LogController,
    uuidProvider: UuidProvider
): KeystoreController =
    KeystoreControllerImpl(prefKeys, logController, uuidProvider)

@Factory
fun provideCryptoController(keystoreController: KeystoreController): CryptoController =
    CryptoControllerImpl(keystoreController)

@Factory
fun provideFormValidator(logController: LogController): FormValidator =
    FormValidatorImpl(logController)

@Factory
fun provideFiltersValidator(): FilterValidator = FilterValidatorImpl()

@Single
fun provideUuidProvider(): UuidProvider {
    return UuidProviderImpl()
}

@Single
fun provideElapsedRealtimeClock(): ElapsedRealtimeClock =
    ElapsedRealtimeClock { SystemClock.elapsedRealtime() }

@Single
fun provideBootIdProvider(context: Context): BootIdProvider = BootIdProvider {
    // BOOT_COUNT is monotonically incremented on every device boot since API 24 and
    // cannot be reset without a factory reset. Fall back to a sentinel if unavailable,
    // in which case lockouts simply retain their legacy behaviour (still safe — only
    // adds a reboot-relief equal to one full duration).
    Settings.Global.getString(context.contentResolver, Settings.Global.BOOT_COUNT) ?: "unknown"
}

