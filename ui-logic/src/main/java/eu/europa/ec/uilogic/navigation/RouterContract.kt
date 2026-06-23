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

package eu.europa.ec.uilogic.navigation

interface NavigatableItem

open class Screen(name: String, parameters: String = "") : NavigatableItem {
    val screenRoute: String = name + parameters
    val screenName = name
}

sealed class StartupScreens {
    data object Splash : Screen(name = "SPLASH")
    data object HardwareKeystoreBlock : Screen(name = "HARDWARE_KEYSTORE_BLOCK")
}

sealed class OnboardingScreens {
    data object Welcome : Screen(name = "WELCOME")
    data object Consent : Screen(name = "CONSENT")
    data object Enrollment : Screen(name = "ENROLLMENT")

    data object TokenQrIntro : Screen(name = "TOKEN_QR_INTRO")

    // Identity Document Verification
    data object DocumentScanIntro : Screen(name = "DOCUMENT_SCAN_INTRO")
    data object DocumentIdentification : Screen(name = "DOCUMENT_IDENTIFICATION")
    data object PassportBiometrics : Screen(name = "PASSPORT_BIOMETRICS")
    data object PassportLiveVideo : Screen(
        name = "PASSPORT_LIVE_VIDEO",
        parameters = "?passportLiveVideoConfig={passportLiveVideoConfig}"
    )
    data object IdentityDocumentCredentialIssuance : Screen(
        name = "IDENTITY_DOCUMENT_CREDENTIAL_ISSUANCE"
    )
}

sealed class CommonScreens {
    data object Success : Screen(name = "SUCCESS", parameters = "?successConfig={successConfig}")
    data object Biometric : Screen(
        name = "BIOMETRIC",
        parameters = "?biometricConfig={biometricConfig}"
    )

    data object BiometricLoginSuccessful : Screen("BIOMETRIC_LOGIN_SUCCESSFUL")

    data object BiometricSetup : Screen("BIOMETRIC_SETUP")

    data object QuickPin :
        Screen(name = "QUICK_PIN", parameters = "?pinFlow={pinFlow}")

    data object QrScan : Screen(
        name = "QR_SCAN",
        parameters = "?qrScanConfig={qrScanConfig}"
    )
}

sealed class PresentationScreens {
    data object PresentationRequest : Screen(
        name = "PRESENTATION_REQUEST",
        parameters = "?requestUriConfig={requestUriConfig}"
    )

    data object PresentationLoading : Screen(name = "PRESENTATION_LOADING")

    data object PresentationSuccess : Screen(name = "PRESENTATION_SUCCESS")
}

sealed class IssuanceScreens {
    data object AddDocument : Screen(
        name = "ISSUANCE_ADD_DOCUMENT",
        parameters = "?issuanceConfig={issuanceConfig}"
    )

    data object DocumentOffer : Screen(
        name = "ISSUANCE_DOCUMENT_OFFER",
        parameters = "?offerConfig={offerConfig}"
    )

    data object DocumentOfferCode : Screen(
        name = "ISSUANCE_DOCUMENT_OFFER_CODE",
        parameters = "?offerCodeConfig={offerCodeConfig}"
    )

    data object DocumentIssuanceSuccess : Screen(
        name = "ISSUANCE_DOCUMENT_SUCCESS",
        parameters = "?issuanceSuccessConfig={issuanceSuccessConfig}"
    )
}

sealed class LandingScreens {
    data object Settings : Screen(name = "SETTINGS")
    data object Landing : Screen(name = "LANDING")
}

sealed class ModuleRoute(val route: String) : NavigatableItem {
    data object StartupModule : ModuleRoute("STARTUP_MODULE")
    data object CommonModule : ModuleRoute("COMMON_MODULE")
    data object PresentationModule : ModuleRoute("PRESENTATION_MODULE")
    data object IssuanceModule : ModuleRoute("ISSUANCE_MODULE")
    data object LandingModule : ModuleRoute("LANDING_MODULE")
    data object OnboardingModule : ModuleRoute("ONBOARDING_MODULE")
}
