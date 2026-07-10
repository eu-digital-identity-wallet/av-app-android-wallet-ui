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

package eu.europa.ec.assemblylogic

import android.app.Application
import androidx.lifecycle.Lifecycle.Event.ON_STOP
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.ProcessLifecycleOwner
import androidx.lifecycle.lifecycleScope
import androidx.work.ExistingPeriodicWorkPolicy.KEEP
import androidx.work.PeriodicWorkRequest
import androidx.work.WorkManager
import eu.europa.ec.analyticslogic.controller.AnalyticsController
import eu.europa.ec.assemblylogic.di.setupKoin
import eu.europa.ec.authenticationlogic.provider.VaultKeyProvider
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.corelogic.config.WalletCoreConfig
import eu.europa.ec.corelogic.worker.RevocationWorkManager
import eu.europa.ec.corelogic.worker.RevocationWorkManager.Companion.REVOCATION_WORK_NAME
import eu.europa.ec.storagelogic.storage.DatabaseManager
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import org.koin.android.ext.android.inject
import org.koin.core.KoinApplication

class Application : Application() {

    private val analyticsController: AnalyticsController by inject()
    private val walletCoreConfig: WalletCoreConfig by inject()
    private val vaultKeyProvider: VaultKeyProvider by inject()
    private val logController: LogController by inject()
    override fun onCreate() {
        super.onCreate()
        initializeKoin()
        initializeReporting()
        initializeRevocationWorkManager()
        initializeVaultKeyLocking()
    }

    private fun initializeKoin(): KoinApplication {
        return setupKoin()
    }

    private fun initializeReporting() {
        analyticsController.initialize(this)
    }

    private fun initializeVaultKeyLocking() {
        // Wipes the in-memory vault key when backgrounded (defense against memory forensics).
        // Re-authentication is not required on foreground because this app displays no sensitive
        // PII on the landing screen; credential sharing always requires PIN/biometric regardless.
        ProcessLifecycleOwner.get().lifecycle.addObserver(
            LifecycleEventObserver { _, event ->
                if (event == ON_STOP && vaultKeyProvider.isUnlocked()) {
                    val database: DatabaseManager by inject()
                    database.close()
                    vaultKeyProvider.lock()
                }
            }
        )
    }

    private fun initializeRevocationWorkManager() {
        val periodicWorkRequest = PeriodicWorkRequest.Builder(
            workerClass = RevocationWorkManager::class.java,
            repeatInterval = walletCoreConfig.revocationInterval,
        ).build()

        ProcessLifecycleOwner.get().lifecycleScope.launch {
            vaultKeyProvider.unlocked.collectLatest { isUnlocked ->
                logController.d { "lock state is: $isUnlocked" }
                val workManager = WorkManager.getInstance(this@Application)
                if (isUnlocked) {
                    workManager.enqueueUniquePeriodicWork(
                        REVOCATION_WORK_NAME,
                        KEEP, periodicWorkRequest
                    )
                } else {
                    workManager.cancelUniqueWork(REVOCATION_WORK_NAME)
                }
            }
        }
    }
}
