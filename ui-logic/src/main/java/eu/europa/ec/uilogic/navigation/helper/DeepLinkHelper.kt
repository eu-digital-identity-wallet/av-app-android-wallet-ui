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

package eu.europa.ec.uilogic.navigation.helper

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.core.os.bundleOf
import eu.europa.ec.businesslogic.util.InProcessEventBus
import androidx.navigation.NavController
import eu.europa.ec.businesslogic.extension.toUri
import eu.europa.ec.businesslogic.util.safeLet
import eu.europa.ec.corelogic.util.CoreActions
import eu.europa.ec.uilogic.BuildConfig
import eu.europa.ec.uilogic.container.EudiComponentActivity
import eu.europa.ec.uilogic.extension.openUrl
import eu.europa.ec.uilogic.navigation.IssuanceScreens
import eu.europa.ec.uilogic.navigation.PresentationScreens
import eu.europa.ec.uilogic.navigation.Screen

fun <T> generateComposableArguments(arguments: Map<String, T>): String {
    if (arguments.isEmpty()) return ""
    return StringBuilder().apply {
        append("?")
        arguments.onEachIndexed { index, entry ->
            if (index > 0) {
                append("&")
            }
            append("${entry.key}=${entry.value}")
        }
    }.toString()
}

fun generateComposableDeepLinkUri(screen: Screen, arguments: String): Uri =
    generateComposableDeepLinkUri(screen.screenName, arguments)

fun generateComposableDeepLinkUri(screen: String, arguments: String): Uri =
    "${BuildConfig.DEEPLINK}/${screen}$arguments".toUri()

fun generateComposableNavigationLink(screen: Screen, arguments: String): String =
    generateComposableNavigationLink(screen.screenName, arguments)

fun generateComposableNavigationLink(screen: String, arguments: String): String =
    "${screen}$arguments"

fun generateNewTaskDeepLink(
    context: Context,
    screen: Screen,
    arguments: String = "",
    flags: Int = 0
): Intent =
    generateNewTaskDeepLink(context, screen.screenName, arguments, flags)

fun generateNewTaskDeepLink(
    context: Context,
    screen: String,
    arguments: String = "",
    flags: Int = 0
): Intent =
    Intent(
        Intent.ACTION_VIEW,
        generateComposableDeepLinkUri(screen, arguments),
        context,
        EudiComponentActivity::class.java
    ).apply {
        addFlags(flags)
    }

private val CREDENTIAL_OFFER_PARAMETERS = listOf("credential_offer", "credential_offer_uri")

fun hasDeepLink(deepLinkUri: Uri?): DeepLinkAction? {
    return safeLet(
        deepLinkUri,
        deepLinkUri?.scheme
    ) { uri, scheme ->
        DeepLinkAction(link = uri, type = DeepLinkType.parse(scheme, uri.host))
            .takeUnless { it.type == DeepLinkType.CREDENTIAL_OFFER && !uri.isCredentialOffer() }
    }
}

private fun Uri.isCredentialOffer(): Boolean =
    isHierarchical
            && (host.isNullOrEmpty() || host.equals(BuildConfig.CREDENTIAL_OFFER_LEGACY_HOST, ignoreCase = true))
            && CREDENTIAL_OFFER_PARAMETERS.any { !getQueryParameter(it).isNullOrBlank() }

fun handleDeepLinkAction(
    navController: NavController,
    uri: Uri,
    arguments: String? = null
) {
    hasDeepLink(uri)?.let { action ->
        handleDeepLinkAction(navController, action, arguments)
    }
}

fun handleDeepLinkAction(
    navController: NavController,
    action: DeepLinkAction,
    arguments: String? = null
) {
    val screen: Screen

    when (action.type) {
        DeepLinkType.OPENID4VP -> {
            screen = PresentationScreens.PresentationRequest
        }

        DeepLinkType.CREDENTIAL_OFFER -> {
            screen = IssuanceScreens.DocumentOffer
        }

        DeepLinkType.ISSUANCE -> {
            notify(
                navController.context,
                CoreActions.VCI_RESUME_ACTION,
                bundleOf(Pair("uri", action.link.toString()))
            )
            return
        }

        DeepLinkType.EXTERNAL -> {
            navController.context.openUrl(action.link)
            return
        }

        DeepLinkType.DYNAMIC_PRESENTATION -> {
            notify(
                navController.context,
                CoreActions.VCI_DYNAMIC_PRESENTATION,
                bundleOf(Pair("uri", action.link.toString()))
            )
            return
        }
    }

    val navigationLink = arguments?.let {
        generateComposableNavigationLink(
            screen = screen,
            arguments = arguments
        )
    } ?: screen.screenRoute

    navController.navigate(navigationLink) {
        popUpTo(screen.screenRoute) { inclusive = true }
    }
}

data class DeepLinkAction(val link: Uri, val type: DeepLinkType)
enum class DeepLinkType(val schemas: List<String>, val host: String? = null) {

    OPENID4VP(
        schemas = listOf(
            BuildConfig.OPENID4VP_SCHEME,
            BuildConfig.EUDI_OPENID4VP_SCHEME,
            BuildConfig.MDOC_OPENID4VP_SCHEME,
            BuildConfig.AVSP_SCHEME,
            BuildConfig.AV_SCHEME
        )
    ),
    CREDENTIAL_OFFER(
        schemas = listOf(
            BuildConfig.CREDENTIAL_OFFER_SCHEME
        )
    ),
    ISSUANCE(
        schemas = listOf(BuildConfig.ISSUE_AUTHORIZATION_SCHEME),
        host = BuildConfig.ISSUE_AUTHORIZATION_HOST
    ),
    EXTERNAL(
        emptyList()
    ),
    DYNAMIC_PRESENTATION(
        emptyList()
    );

    companion object {
        fun parse(scheme: String, host: String? = null): DeepLinkType = when {

            OPENID4VP.schemas.contains(scheme) -> {
                OPENID4VP
            }

            CREDENTIAL_OFFER.schemas.contains(scheme) -> {
                CREDENTIAL_OFFER
            }

            ISSUANCE.schemas.contains(scheme) && host == ISSUANCE.host -> {
                ISSUANCE
            }

            else -> EXTERNAL
        }
    }
}

private fun notify(context: Context, action: String, bundle: Bundle? = null) {
    Intent().also { intent ->
        intent.action = action
        bundle?.let { intent.putExtras(it) }
        InProcessEventBus.send(intent)
    }
}