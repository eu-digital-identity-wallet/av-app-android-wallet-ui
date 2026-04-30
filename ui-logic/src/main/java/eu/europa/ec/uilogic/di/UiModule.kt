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

package eu.europa.ec.uilogic.di

import eu.europa.ec.analyticslogic.controller.AnalyticsController
import eu.europa.ec.businesslogic.provider.ElapsedRealtimeClock
import eu.europa.ec.uilogic.config.ConfigUILogic
import eu.europa.ec.uilogic.config.ConfigUILogicImpl
import eu.europa.ec.uilogic.navigation.RouterHost
import eu.europa.ec.uilogic.navigation.RouterHostImpl
import eu.europa.ec.uilogic.navigation.helper.DcApiIntentHolder
import eu.europa.ec.uilogic.serializer.UiSerializer
import eu.europa.ec.uilogic.serializer.UiSerializerImpl
import org.koin.core.annotation.ComponentScan
import org.koin.core.annotation.Factory
import org.koin.core.annotation.Module
import org.koin.core.annotation.Single

@Module
@ComponentScan("eu.europa.ec.uilogic")
class LogicUiModule

@Single
fun provideRouterHost(
    configUILogic: ConfigUILogic,
    analyticsController: AnalyticsController
): RouterHost = RouterHostImpl(configUILogic, analyticsController)

@Factory
fun provideUiSerializer(): UiSerializer = UiSerializerImpl()

@Single
fun provideConfigUILogic(): ConfigUILogic = ConfigUILogicImpl()

@Single
fun provideDcApiIntentHolder(clock: ElapsedRealtimeClock): DcApiIntentHolder =
    DcApiIntentHolder(clock)

