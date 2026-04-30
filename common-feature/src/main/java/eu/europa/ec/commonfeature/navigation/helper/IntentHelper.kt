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

package eu.europa.ec.commonfeature.navigation.helper

import androidx.navigation.NavController
import eu.europa.ec.commonfeature.config.PresentationMode
import eu.europa.ec.commonfeature.config.RequestUriConfig
import eu.europa.ec.uilogic.navigation.PresentationScreens
import eu.europa.ec.uilogic.navigation.helper.DcApiIntentHolder
import eu.europa.ec.uilogic.navigation.helper.IntentAction
import eu.europa.ec.uilogic.navigation.helper.generateComposableArguments
import eu.europa.ec.uilogic.navigation.helper.generateComposableNavigationLink
import eu.europa.ec.uilogic.navigation.helper.isDCAPIIntent
import eu.europa.ec.uilogic.serializer.UiSerializer
import org.koin.java.KoinJavaComponent.inject

fun handleIntentAction(
    navController: NavController,
    intentAction: IntentAction,
) {
    if (isDCAPIIntent(intentAction.intent)) {
        val dcApiIntentHolder: DcApiIntentHolder by inject(DcApiIntentHolder::class.java)
        dcApiIntentHolder.cacheIntent(intentAction.intent)

        val uiSerializer: UiSerializer by inject(UiSerializer::class.java)

        val config = RequestUriConfig(
            presentationMode = PresentationMode.DcApi
        )

        val arguments = generateComposableArguments(
            mapOf(
                RequestUriConfig.serializedKeyName to uiSerializer.toBase64(
                    config,
                    RequestUriConfig.Parser
                ).orEmpty()
            )
        )

        val navigationLink = generateComposableNavigationLink(
            screen = PresentationScreens.PresentationRequest,
            arguments = arguments
        )

        navController.navigate(navigationLink) {
            popUpTo(PresentationScreens.PresentationRequest.screenRoute) { inclusive = true }
        }
    }
}
