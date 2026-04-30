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

package eu.europa.ec.assemblylogic.ui

import android.os.Bundle
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import eu.europa.ec.commonfeature.router.featureCommonGraph
import eu.europa.ec.issuancefeature.router.featureIssuanceGraph
import eu.europa.ec.landingfeature.router.featureLandingGraph
import eu.europa.ec.onboardingfeature.router.featureOnboardingGraph
import eu.europa.ec.presentationfeature.router.presentationGraph
import eu.europa.ec.startupfeature.router.featureStartupGraph
import eu.europa.ec.uilogic.container.EudiComponentActivity

// Intentional: FLAG_SECURE is not set. This wallet displays only age-over-X boolean
// attestations — no passport images, document numbers, or sensitive PII appear on screen.
// The PIN field already masks input. Teams adding richer credential display should set
// window.setFlags(FLAG_SECURE, FLAG_SECURE) in onCreate() before calling super.
class MainActivity : EudiComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {

        // Since current app only supports the light mode, forcing it to the light mode.
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.light(
                scrim = Color.Transparent.toArgb(),
                darkScrim = Color.Transparent.toArgb()
            ),
            navigationBarStyle = SystemBarStyle.light(
                scrim = Color.Transparent.toArgb(),
                darkScrim = Color.Transparent.toArgb()
            )
        )

        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            Content(intent) {
                featureStartupGraph(it)
                featureOnboardingGraph(it)
                featureCommonGraph(it)
                presentationGraph(it)
                featureIssuanceGraph(it)
                featureLandingGraph(it)
            }
        }
    }
}
