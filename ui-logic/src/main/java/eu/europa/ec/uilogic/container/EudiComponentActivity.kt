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

package eu.europa.ec.uilogic.container

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.resourceslogic.theme.ThemeManager
import eu.europa.ec.uilogic.extension.exposeTestTagsAsResourceId
import eu.europa.ec.uilogic.navigation.IssuanceScreens
import eu.europa.ec.uilogic.navigation.RouterHost
import eu.europa.ec.uilogic.navigation.helper.DeepLinkAction
import eu.europa.ec.uilogic.navigation.helper.DeepLinkType
import eu.europa.ec.uilogic.navigation.helper.handleDeepLinkAction
import eu.europa.ec.uilogic.navigation.helper.hasDeepLink
import eu.europa.ec.uilogic.navigation.helper.isDCAPIIntent
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.koin.android.ext.android.inject
import org.koin.core.annotation.KoinExperimentalAPI

open class EudiComponentActivity : FragmentActivity() {

    private val routerHost: RouterHost by inject()
    private val logController: LogController by inject()

    private var flowStarted: Boolean = false

    internal var pendingDeepLink: Uri? = null
    internal var pendingIntent: Intent? = null

    internal fun cacheDeepLink(intent: Intent?) {
        pendingDeepLink = intent?.data
    }

    internal fun cacheIntent(intent: Intent?) {
        pendingIntent = intent
    }

    @OptIn(KoinExperimentalAPI::class)
    @Composable
    protected fun Content(
        intent: Intent?,
        builder: NavGraphBuilder.(NavController) -> Unit
    ) {
        logController.d("DCAPI") { "Content called with intent: $intent, action: ${intent?.action}" }
        ThemeManager.instance.Theme(darkTheme = false) {
            Surface(
                modifier = Modifier
                    .exposeTestTagsAsResourceId()
                    .fillMaxSize(),
                color = MaterialTheme.colorScheme.surface
            ) {
                routerHost.StartFlow {
                    builder(it)
                }
                flowStarted = true
                logController.i("DCAPI") { "Flow started, calling handleDeepLink" }
                handleDeepLink(intent, coldBoot = true)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (flowStarted) {
            handleDeepLink(intent)
        } else {
            runPendingDeepLink(intent)
        }
    }

    private fun runPendingDeepLink(intent: Intent?) {
        lifecycleScope.launch {
            var count = 0
            while (!flowStarted && count <= 10) {
                count++
                delay(500)
            }
            if (count <= 10) {
                handleDeepLink(intent)
            }
        }
    }

    private fun handleDeepLink(intent: Intent?, coldBoot: Boolean = false) {
        logController.d("DeepLink") { "Handling deep link: ${intent?.data}, action: ${intent?.action}" }

        // Handle DCAPI intents
        if (isDCAPIIntent(intent)) {
            logController.d("DCAPI") { "Detected DCAPI intent: ${intent?.action}" }

            // Intentional: the intent is cached before the PIN/biometric check so that it
            // survives the authentication flow and can be consumed after login completes.
            // The presentation screen shows the request source and requires PIN/biometric
            // before sharing any data, so no re-authentication gate is needed here.
            // The cache has a 60-second TTL (DcApiIntentHolder) to prevent stale-intent replay.
            cacheIntent(intent)
            logController.i("DCAPI") { "Cached DCAPI intent for later retrieval" }

            logController.d("DCAPI") {
                val loggedInWithDocuments: Boolean = routerHost.userIsLoggedInWithDocuments()
                "User logged in with documents: $loggedInWithDocuments"
            }
            if (routerHost.userIsLoggedInWithDocuments()) {
                logController.i("DCAPI") { "Navigating to landing screen" }
                routerHost.popToLandingScreen()
            } else {
                logController.i("DCAPI") { "User needs to login first, intent is cached for after PIN entry" }
            }
            setIntent(Intent())
            return
        }

        hasDeepLink(intent?.data)?.let {
            if (it.type == DeepLinkType.ISSUANCE && !coldBoot) {
                handleDeepLinkAction(
                    routerHost.getNavController(),
                    it.link
                )
            } else if (
                it.type == DeepLinkType.CREDENTIAL_OFFER
                && !routerHost.userIsLoggedInWithDocuments()
                && routerHost.userIsLoggedInWithNoDocuments()
            ) {
                cacheDeepLink(intent)
                routerHost.popToIssuanceOnboardingScreen()
            } else if (it.type == DeepLinkType.OPENID4VP
                && routerHost.userIsLoggedInWithDocuments()
                && (routerHost.isScreenOnBackStackOrForeground(IssuanceScreens.AddDocument)
                        || routerHost.isScreenOnBackStackOrForeground(IssuanceScreens.DocumentOffer))
            ) {
                handleDeepLinkAction(
                    routerHost.getNavController(),
                    DeepLinkAction(it.link, DeepLinkType.DYNAMIC_PRESENTATION)
                )
            } else if (it.type != DeepLinkType.ISSUANCE) {
                cacheDeepLink(intent)
                if (routerHost.userIsLoggedInWithDocuments()) {
                    routerHost.popToLandingScreen()
                }
            }
            setIntent(Intent())
        }
    }
}