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

package eu.europa.ec.corelogic.config

import android.content.Context
import eu.europa.ec.corelogic.BuildConfig
import eu.europa.ec.eudi.wallet.EudiWalletConfig
import eu.europa.ec.eudi.wallet.issue.openid4vci.OpenId4VciManager
import eu.europa.ec.eudi.wallet.issue.openid4vci.dpop.DPopConfig
import eu.europa.ec.eudi.wallet.transfer.openId4vp.ClientIdScheme
import eu.europa.ec.eudi.wallet.transfer.openId4vp.Format
import eu.europa.ec.eudi.wallet.zkp.LongfellowCircuits
import eu.europa.ec.eudi.wallet.zkp.LongfellowZkSystemRepository
import eu.europa.ec.resourceslogic.R
import kotlin.time.Duration.Companion.seconds

internal class WalletCoreConfigImpl(
    private val context: Context
) : WalletCoreConfig {

    private var _config: EudiWalletConfig? = null

    override val config: EudiWalletConfig
        get() {
            if (_config == null) {
                _config = EudiWalletConfig {
                    configureDocumentKeyCreation(
                        userAuthenticationRequired = true,
                        userAuthenticationTimeout = 10.seconds,
                        useStrongBoxForKeys = true
                    )
                    configureOpenId4Vp {
                        withClientIdSchemes(
                            listOf(
                                ClientIdScheme.RedirectUri
                            )
                        )
                        withSchemes(
                            listOf(
                                // Add your new scheme here and to DeepLinkHelper/DeepLinkType to solve "Not supported scheme" error
                                BuildConfig.OPENID4VP_SCHEME,
                                BuildConfig.EUDI_OPENID4VP_SCHEME,
                                BuildConfig.MDOC_OPENID4VP_SCHEME,
                                BuildConfig.AVSP_SCHEME,
                                BuildConfig.AV_SCHEME
                            )
                        )
                        withFormats(
                            Format.MsoMdoc.ES256,
                        )
                    }

                    configureReaderTrustStore(
                        context,
                        R.raw.av_issuer_ca01
                    )

                    configureDCAPI {
                        withEnabled(true)
                    }

                    configureZkp(
                        LongfellowZkSystemRepository(
                            circuits = LongfellowCircuits.get(context)
                        ).build()
                    )
                }
            }
            return _config!!
        }

    override val vciConfig: List<OpenId4VciManager.Config>
        get() = listOf(
            OpenId4VciManager.Config.Builder()
                .withIssuerUrl(issuerUrl = "https://test.issuer.dev.ageverification.dev") // no end slash
                .withClientAuthenticationType(OpenId4VciManager.ClientAuthenticationType.AttestationBased)
                .withAuthFlowRedirectionURI(BuildConfig.ISSUE_AUTHORIZATION_DEEPLINK)
                .withParUsage(OpenId4VciManager.Config.ParUsage.NEVER)
                .withDPopConfig(DPopConfig.Default)
                .build()
        )

    /**
     * Configuration for the passport scanning issuer.
     */
    override val passportScanningIssuerConfig: OpenId4VciManager.Config =
        OpenId4VciManager.Config.Builder()
            .withIssuerUrl(issuerUrl = "https://passport.issuer.dev.ageverification.dev") // no end slash
            .withClientAuthenticationType(OpenId4VciManager.ClientAuthenticationType.AttestationBased)
            .withAuthFlowRedirectionURI(BuildConfig.ISSUE_AUTHORIZATION_DEEPLINK)
            .withParUsage(OpenId4VciManager.Config.ParUsage.NEVER)
            .withDPopConfig(DPopConfig.Default)
            .build()

    /**
     * Configuration for the face match SDK.
     */
    override val faceMatchConfig: FaceMatchConfig = FaceMatchConfig(
        faceDetectorModel = FaceMatchModelSource.Asset("mediapipe_long.onnx"),
        embeddingExtractorModel = FaceMatchModelSource.Remote(
            url = "https://github.com/eu-digital-identity-wallet/av-app-android-wallet-ui/releases/download/2025.10-2/glintr100.onnx",
            sha256Hex = "a7933ea5330113b01c9b60351d8f4c33003f145d8470ac5f0e52ee2effe25c60",
        ),
        livenessModel0 = FaceMatchModelSource.Asset("silentface40.onnx"),
        livenessModel1 = FaceMatchModelSource.Asset("silentface27.onnx"),
        livenessThreshold = 0.972017,
        matchingThreshold = 0.5,
    )

    override val walletProviderHost: String
        get() = "https://wallet-provider.ageverification.dev"
}
