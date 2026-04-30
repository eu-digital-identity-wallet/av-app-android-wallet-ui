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

import eu.europa.ec.corelogic.model.DocumentCategories
import eu.europa.ec.corelogic.model.DocumentCategory
import eu.europa.ec.corelogic.model.DocumentIdentifier
import eu.europa.ec.eudi.wallet.EudiWalletConfig
import eu.europa.ec.eudi.wallet.document.CreateDocumentSettings.CredentialPolicy
import eu.europa.ec.eudi.wallet.issue.openid4vci.OpenId4VciManager
import java.time.Duration

/**
 * Where a face-match model is loaded from. The sealed hierarchy couples a remote URL
 * to its expected SHA-256 so a configuration cannot supply a URL without a pinned hash.
 */
sealed interface FaceMatchModelSource {
    /** Model shipped inside the APK as an asset file. */
    data class Asset(val filename: String) : FaceMatchModelSource

    /**
     * Model fetched from [url] (must be https) and verified against [sha256Hex]
     * (case-insensitive hex digest). Downloads whose hash does not match are discarded.
     */
    data class Remote(val url: String, val sha256Hex: String) : FaceMatchModelSource
}

/**
 * Configuration for Face Match SDK used in passport verification
 */
data class FaceMatchConfig(
    val faceDetectorModel: FaceMatchModelSource,
    val embeddingExtractorModel: FaceMatchModelSource,
    val livenessModel0: FaceMatchModelSource,
    val livenessModel1: FaceMatchModelSource,
    val livenessThreshold: Double,
    /** Minimum cosine-similarity score to accept as the same subject. Recommended to be >= 0.8. */
    val matchingThreshold: Double,
)

interface WalletCoreConfig {


    /**
     * Holds the configuration settings for the EudiWallet.
     * This configuration includes settings such as API endpoints, cryptographic parameters,
     * and storage locations.
     */
    val config: EudiWalletConfig

    /**
     * List of Configurations for Verifiable Credentials Issuance (VCI).
     */
    val vciConfig: List<OpenId4VciManager.Config>

    /**
     * Returns a predefined set of document categories and their associated identifiers.
     *
     * This property provides a structured mapping of common document categories (e.g., Government, Travel, Finance)
     * to specific document identifiers.  These identifiers are used to uniquely identify different types of
     * documents within a given category and are based on standard formats and specifications.
     *
     * The structure is a map where:
     * - Keys are [DocumentCategory] enum values representing broad document types.
     * - Values are lists of [DocumentIdentifier] objects, each representing a specific document type within that category.
     *
     * The supported document identifiers utilize various formats, including:
     * - Predefined types like [DocumentIdentifier.MdocPid] and [DocumentIdentifier.SdJwtPid].
     * - Formats defined by ISO standards (e.g., "org.iso.18013.5.1.mDL", "org.iso.23220.2.photoid.1").
     * - Formats specified by the European Union (e.g., "eu.europa.ec.eudi.tax.1", "eu.europa.ec.eudi.iban.1").
     * - URNs following the "urn:eu.europa.ec.eudi" namespace (e.g., "urn:eu.europa.ec.eudi:tax:1", "urn:eu.europa.ec.eudi:iban:1").
     *
     * The "Other" category is used for identifiers that don't fit neatly into the other predefined categories.
     *
     * Note:  An empty list for a category (e.g., Education) indicates that no specific document identifiers are
     * currently defined for that category.
     */
    val documentCategories: DocumentCategories
        get() = DocumentCategories(
            value = mapOf(
                DocumentCategory.Government to listOf(
                    DocumentIdentifier.MdocPid,
                    DocumentIdentifier.SdJwtPid,
                    DocumentIdentifier.OTHER(
                        formatType = "org.iso.18013.5.1.mDL"
                    ),
                    DocumentIdentifier.OTHER(
                        formatType = "eu.europa.ec.eudi.tax.1"
                    ),
                    DocumentIdentifier.OTHER(
                        formatType = "urn:eu.europa.ec.eudi:tax:1"
                    ),
                    DocumentIdentifier.OTHER(
                        formatType = "eu.europa.ec.eudi.pseudonym.age_over_18.1"
                    ),
                    DocumentIdentifier.OTHER(
                        formatType = "urn:eu.europa.ec.eudi:pseudonym_age_over_18:1"
                    ),
                    DocumentIdentifier.OTHER(
                        formatType = "eu.europa.ec.eudi.pseudonym.age_over_18.deferred_endpoint"
                    ),
                    DocumentIdentifier.OTHER(
                        formatType = "eu.europa.ec.eudi.cor.1"
                    ),
                ),
                DocumentCategory.Travel to listOf(
                    DocumentIdentifier.OTHER(
                        formatType = "org.iso.23220.2.photoid.1"
                    ),
                    DocumentIdentifier.OTHER(
                        formatType = "org.iso.23220.photoID.1"
                    ),
                    DocumentIdentifier.OTHER(
                        formatType = "org.iso.18013.5.1.reservation"
                    ),
                ),
                DocumentCategory.Finance to listOf(
                    DocumentIdentifier.OTHER(
                        formatType = "eu.europa.ec.eudi.iban.1"
                    ),
                    DocumentIdentifier.OTHER(
                        formatType = "urn:eu.europa.ec.eudi:iban:1"
                    ),
                ),
                DocumentCategory.Education to emptyList(),
                DocumentCategory.Health to listOf(
                    DocumentIdentifier.OTHER(
                        formatType = "eu.europa.ec.eudi.hiid.1"
                    ),
                    DocumentIdentifier.OTHER(
                        formatType = "urn:eu.europa.ec.eudi:hiid:1"
                    ),
                    DocumentIdentifier.OTHER(
                        formatType = "eu.europa.ec.eudi.ehic.1"
                    ),
                    DocumentIdentifier.OTHER(
                        formatType = "urn:eu.europa.ec.eudi:ehic:1"
                    ),
                ),
                DocumentCategory.SocialSecurity to listOf(
                    DocumentIdentifier.OTHER(
                        formatType = "eu.europa.ec.eudi.pda1.1"
                    ),
                    DocumentIdentifier.OTHER(
                        formatType = "urn:eu.europa.ec.eudi:pda1:1"
                    ),
                ),
                DocumentCategory.Retail to listOf(
                    DocumentIdentifier.OTHER(
                        formatType = "eu.europa.ec.eudi.loyalty.1"
                    ),
                    DocumentIdentifier.OTHER(
                        formatType = "eu.europa.ec.eudi.msisdn.1"
                    ),
                    DocumentIdentifier.OTHER(
                        formatType = "urn:eu.europa.ec.eudi:msisdn:1"
                    ),
                ),
                DocumentCategory.Other to listOf(
                    DocumentIdentifier.OTHER(
                        formatType = "eu.europa.ec.eudi.por.1"
                    ),
                    DocumentIdentifier.OTHER(
                        formatType = "urn:eu.europa.ec.eudi:por:1"
                    ),
                ),
            )
        )

    /**
     * The interval at which revocations are checked.
     *
     * This property defines the time interval between checks for revoked tokens or credentials.
     * It is currently set to 15 minutes.
     */
    val revocationInterval: Duration get() = Duration.ofMinutes(15)

    /**
     * Configuration for document issuance, including default rules and specific overrides.
     *
     * This property defines the behavior for how many credentials of each document type are issued
     * and their usage policy (e.g., rotate use, one-time use).
     *
     * It consists of:
     * - `defaultRule`: A [DocumentIssuanceRule] that applies to all document types unless overridden.
     *   By default, it uses [CredentialPolicy.RotateUse] and issues 1 credential.
     * - `documentSpecificRules`: A map allowing overrides for specific document types.
     *   - Keys are [DocumentIdentifier] objects representing specific document types.
     *   - Values are [DocumentIssuanceRule] objects defining the policy and number of credentials for that document.
     *
     * For example:
     * - [DocumentIdentifier.MdocPid] is configured for [CredentialPolicy.OneTimeUse] with 10 credentials.
     * - [DocumentIdentifier.SdJwtPid] is configured for [CredentialPolicy.OneTimeUse] with 10 credentials.
     *
     * Any document type not listed in `documentSpecificRules` will use the `defaultRule`.
     */
    val documentIssuanceConfig: DocumentIssuanceConfig
        get() = DocumentIssuanceConfig(
            defaultRule = DocumentIssuanceRule(
                policy = CredentialPolicy.OneTimeUse,
                numberOfCredentials = 30
            ),
            documentSpecificRules = mapOf()
        )

    /**
     * Configuration for the passport scanning issuer.
     *
     * This configuration is used for issuing age verification documents after passport scanning.
     * It points to a separate issuer endpoint that handles the passport-based issuance flow.
     *
     * @return The OpenId4VciManager.Config for the passport scanning issuer, or null if not configured
     */
    val passportScanningIssuerConfig: OpenId4VciManager.Config?
        get() = null

    /**
     * Configuration for the face match SDK used in passport verification.
     *
     * This configuration defines the model files (local assets or remote URLs) and thresholds
     * used for face liveness detection and matching during passport verification.
     *
     * @return The FaceMatchConfig with model paths and thresholds
     */
    val faceMatchConfig: FaceMatchConfig

    /**
     * Host for the Wallet Provider.
     */
    val walletProviderHost: String
}