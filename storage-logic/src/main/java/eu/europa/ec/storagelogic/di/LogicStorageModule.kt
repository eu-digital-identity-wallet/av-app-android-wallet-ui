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

package eu.europa.ec.storagelogic.di

import android.content.Context
import eu.europa.ec.authenticationlogic.provider.VaultKeyProvider
import eu.europa.ec.storagelogic.storage.DatabaseManager
import org.koin.core.annotation.ComponentScan
import org.koin.core.annotation.Module
import org.koin.core.annotation.Single

@Module
@ComponentScan("eu.europa.ec.storagelogic")
class LogicStorageModule

@Single
fun provideDatabaseManager(
    context: Context,
    vaultKeyProvider: VaultKeyProvider,
): DatabaseManager = DatabaseManager(context, vaultKeyProvider)
