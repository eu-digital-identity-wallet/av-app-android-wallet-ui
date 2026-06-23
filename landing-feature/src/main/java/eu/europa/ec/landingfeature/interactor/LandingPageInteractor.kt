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

package eu.europa.ec.landingfeature.interactor

import eu.europa.ec.businesslogic.extension.safeAsync
import eu.europa.ec.businesslogic.provider.UuidProvider
import eu.europa.ec.commonfeature.util.transformPathsToDomainClaims
import eu.europa.ec.corelogic.controller.WalletCoreDocumentsController
import eu.europa.ec.corelogic.extension.toClaimPaths
import eu.europa.ec.eudi.wallet.document.format.DocumentClaim
import eu.europa.ec.eudi.wallet.document.format.SdJwtVcClaim
import eu.europa.ec.landingfeature.interactor.LandingPageInteractor.GetAgeCredentialPartialState
import eu.europa.ec.landingfeature.model.AgeCredentialUi
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow


interface LandingPageInteractor {
    fun getAgeCredential(): Flow<GetAgeCredentialPartialState>

    sealed class GetAgeCredentialPartialState {
        data class Success(
            val ageCredentialUi: AgeCredentialUi,
        ) : GetAgeCredentialPartialState()

        data class Failure(val error: String) : GetAgeCredentialPartialState()
    }
}

private fun DocumentClaim.flattenClaims(): List<DocumentClaim> =
    if (this is SdJwtVcClaim && children.isNotEmpty())
        listOf(this) + children.flatMap { it.flattenClaims() }
    else
        listOf(this)

class LandingPageInteractorImpl(
    private val walletCoreDocumentsController: WalletCoreDocumentsController,
    private val resourceProvider: ResourceProvider,
    private val uuidProvider: UuidProvider,
) : LandingPageInteractor {

    private val genericErrorMsg
        get() = resourceProvider.genericErrorMessage()

    override fun getAgeCredential(): Flow<GetAgeCredentialPartialState> =
        flow {
            walletCoreDocumentsController.getAllIssuedDocuments().firstOrNull()?.let {
                val claimsPaths = it.data.claims.flatMap { claim ->
                    claim.toClaimPaths()
                }

                val domainClaims = transformPathsToDomainClaims(
                    paths = claimsPaths,
                    claims = it.data.claims,
                    resourceProvider = resourceProvider,
                    uuidProvider = uuidProvider
                )

                val flatClaims = it.data.claims.flatMap { claim -> claim.flattenClaims() }

                val ageThreshold = flatClaims
                    .filter { claim ->
                        claim.identifier.startsWith("age_over_") &&
                                (claim.value == true ||
                                        claim.value?.toString()?.equals("true", ignoreCase = true) == true)
                    }
                    .mapNotNull { claim ->
                        claim.identifier.removePrefix("age_over_").toIntOrNull()
                    }
                    .maxOrNull()

                val ageCredentialUi = AgeCredentialUi(
                    docId = it.id,
                    claims = domainClaims,
                    credentialCount = it.credentialsCount(),
                    ageThreshold = ageThreshold,
                )

                emit(GetAgeCredentialPartialState.Success(ageCredentialUi))
            } ?: emit(
                GetAgeCredentialPartialState.Failure(
                    resourceProvider.getString(R.string.landing_screen_no_age_credential_found)
                )
            )
        }.safeAsync {
            GetAgeCredentialPartialState.Failure(
                error = it.localizedMessage ?: genericErrorMsg
            )
        }
}


