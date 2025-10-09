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

package eu.europa.ec.onboardingfeature.interactor

import android.content.Context
import eu.europa.ec.authenticationlogic.controller.authentication.BiometricsAvailability
import eu.europa.ec.authenticationlogic.controller.authentication.DeviceAuthenticationResult
import eu.europa.ec.authenticationlogic.model.BiometricCrypto
import eu.europa.ec.commonfeature.config.SuccessUIConfig
import eu.europa.ec.commonfeature.interactor.DeviceAuthenticationInteractor
import eu.europa.ec.corelogic.controller.FetchScopedDocumentsPartialState
import eu.europa.ec.corelogic.controller.IssuanceMethod
import eu.europa.ec.corelogic.controller.IssueDocumentPartialState
import eu.europa.ec.corelogic.controller.PassportScanningDocumentsController
import eu.europa.ec.corelogic.model.ScopedDocument
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.resourceslogic.theme.values.ThemeColors
import eu.europa.ec.uilogic.component.AppIcons
import eu.europa.ec.uilogic.component.utils.PERCENTAGE_25
import eu.europa.ec.uilogic.config.ConfigNavigation
import eu.europa.ec.uilogic.config.NavigationType
import eu.europa.ec.uilogic.navigation.CommonScreens
import eu.europa.ec.uilogic.navigation.LandingScreens
import eu.europa.ec.uilogic.navigation.helper.generateComposableArguments
import eu.europa.ec.uilogic.navigation.helper.generateComposableNavigationLink
import eu.europa.ec.uilogic.serializer.UiSerializer
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow

sealed class CredentialIssuancePartialState {
    data class Success(val documentId: String) : CredentialIssuancePartialState()
    data class DeferredSuccess(val successRoute: String) : CredentialIssuancePartialState()
    data class UserAuthRequired(
        val crypto: BiometricCrypto,
        val resultHandler: DeviceAuthenticationResult,
    ) : CredentialIssuancePartialState()

    data class Failure(val error: String) : CredentialIssuancePartialState()
}

interface PassportCredentialIssuanceInteractor {
    fun issuePassportScanningDocument(context: Context): Flow<CredentialIssuancePartialState>
    fun handleUserAuth(
        context: Context,
        crypto: BiometricCrypto,
        notifyOnAuthenticationFailure: Boolean,
        resultHandler: DeviceAuthenticationResult,
    )

    fun resumeOpenId4VciWithAuthorization(uri: String)
}

class PassportCredentialIssuanceInteractorImpl(
    private val passportScanningDocumentsController: PassportScanningDocumentsController,
    private val deviceAuthenticationInteractor: DeviceAuthenticationInteractor,
    private val resourceProvider: ResourceProvider,
    private val uiSerializer: UiSerializer,
) : PassportCredentialIssuanceInteractor {

    private val genericErrorMsg
        get() = resourceProvider.genericErrorMessage()

    override fun issuePassportScanningDocument(context: Context): Flow<CredentialIssuancePartialState> =
        flow {
            when (val state =
                passportScanningDocumentsController.getPassportScanningScopedDocuments(
                    resourceProvider.getLocale()
                )) {
                is FetchScopedDocumentsPartialState.Success -> {
                    val ageVerificationDocument: ScopedDocument? = state.documents
                        .firstOrNull { it.isAgeVerification }

                    if (ageVerificationDocument == null) {
                        emit(CredentialIssuancePartialState.Failure(genericErrorMsg))
                        return@flow
                    }

                    passportScanningDocumentsController.issuePassportScanningDocument(
                        issuanceMethod = IssuanceMethod.OPENID4VCI,
                        configId = ageVerificationDocument.configurationId
                    ).collect { issueState ->
                        when (issueState) {
                            is IssueDocumentPartialState.Success ->
                                emit(CredentialIssuancePartialState.Success(issueState.documentId))

                            is IssueDocumentPartialState.DeferredSuccess -> {
                                val successRoute = buildGenericSuccessRouteForDeferred()
                                emit(
                                    CredentialIssuancePartialState.DeferredSuccess(
                                        successRoute
                                    )
                                )
                            }

                            is IssueDocumentPartialState.UserAuthRequired ->
                                emit(
                                    CredentialIssuancePartialState.UserAuthRequired(
                                        issueState.crypto,
                                        issueState.resultHandler
                                    )
                                )

                            is IssueDocumentPartialState.Failure ->
                                emit(CredentialIssuancePartialState.Failure(issueState.errorMessage))
                        }
                    }
                }

                is FetchScopedDocumentsPartialState.Failure ->
                    emit(CredentialIssuancePartialState.Failure(state.errorMessage))
            }
        }

    override fun handleUserAuth(
        context: Context,
        crypto: BiometricCrypto,
        notifyOnAuthenticationFailure: Boolean,
        resultHandler: DeviceAuthenticationResult,
    ) {
        deviceAuthenticationInteractor.getBiometricsAvailability {
            when (it) {
                is BiometricsAvailability.CanAuthenticate -> {
                    deviceAuthenticationInteractor.authenticateWithBiometrics(
                        context = context,
                        crypto = crypto,
                        notifyOnAuthenticationFailure = notifyOnAuthenticationFailure,
                        resultHandler = resultHandler
                    )
                }

                is BiometricsAvailability.NonEnrolled -> {
                    deviceAuthenticationInteractor.launchBiometricSystemScreen()
                }

                is BiometricsAvailability.Failure -> {
                    resultHandler.onAuthenticationFailure()
                }
            }
        }
    }

    private fun buildGenericSuccessRouteForDeferred(): String {
        val navigation = ConfigNavigation(
            navigationType = NavigationType.PopTo(
                screen = LandingScreens.Landing
            )
        )
        val successScreenArguments = getSuccessScreenArgumentsForDeferred(navigation)
        return generateComposableNavigationLink(
            screen = CommonScreens.Success,
            arguments = successScreenArguments
        )
    }

    override fun resumeOpenId4VciWithAuthorization(uri: String) {
        passportScanningDocumentsController.resumePassportScanningOpenId4VciWithAuthorization(uri)
    }

    private fun getSuccessScreenArgumentsForDeferred(
        navigation: ConfigNavigation,
    ): String {
        val (textElementsConfig, imageConfig, buttonText) = Triple(
            first = SuccessUIConfig.TextElementsConfig(
                text = resourceProvider.getString(R.string.issuance_add_document_deferred_success_text),
                description = resourceProvider.getString(R.string.issuance_add_document_deferred_success_description),
                color = ThemeColors.pending
            ),
            second = SuccessUIConfig.ImageConfig(
                type = SuccessUIConfig.ImageConfig.Type.Drawable(icon = AppIcons.InProgress),
                tint = ThemeColors.primary,
                screenPercentageSize = PERCENTAGE_25,
            ),
            third = resourceProvider.getString(R.string.issuance_add_document_deferred_success_primary_button_text)
        )

        return generateComposableArguments(
            mapOf(
                SuccessUIConfig.serializedKeyName to uiSerializer.toBase64(
                    SuccessUIConfig(
                        textElementsConfig = textElementsConfig,
                        imageConfig = imageConfig,
                        buttonConfig = listOf(
                            SuccessUIConfig.ButtonConfig(
                                text = buttonText,
                                style = SuccessUIConfig.ButtonConfig.Style.PRIMARY,
                                navigation = navigation
                            )
                        ),
                        onBackScreenToNavigate = navigation,
                    ),
                    SuccessUIConfig.Parser
                ).orEmpty()
            )
        )
    }
}
