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

package eu.europa.ec.testfeature.util

import androidx.annotation.VisibleForTesting
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import org.mockito.kotlin.whenever

@VisibleForTesting(otherwise = VisibleForTesting.Companion.NONE)
object StringResourceProviderMocker {

    /**
     * Mocks ResourceProvider.getString(...) for each (resId → returnValue) pair.
     */
    fun mockResourceProviderStrings(
        resourceProvider: ResourceProvider,
        pairs: List<Pair<Int, String>>,
    ) {
        pairs.forEach { (resId, returnValue) ->
            whenever(resourceProvider.getString(resId)).thenReturn(returnValue)
        }
    }

    fun mockTransformToDocumentDetailsDomainStrings(resourceProvider: ResourceProvider) {
        mockCreateKeyValueStrings(resourceProvider)
    }

    fun mockCreateKeyValueStrings(resourceProvider: ResourceProvider) {
        val mockedStrings = listOf(
            R.string.document_details_boolean_item_true_readable_value to "yes",
            R.string.document_details_boolean_item_false_readable_value to "no",
        )

        mockResourceProviderStrings(resourceProvider, mockedStrings)
        mockGetGenderValueStrings(resourceProvider)
    }

    fun mockGetGenderValueStrings(resourceProvider: ResourceProvider) {
        val mockedStrings = listOf(
            R.string.request_gender_male to "Male",
            R.string.request_gender_female to "Female",
            R.string.request_gender_not_known to "Not known",
            R.string.request_gender_not_applicable to "Not applicable",
        )

        mockResourceProviderStrings(resourceProvider, mockedStrings)
    }

    fun mockTransformToUiItemsStrings(
        resourceProvider: ResourceProvider,
    ) {
        mockCreateKeyValueStrings(resourceProvider)

        whenever(resourceProvider.getLocale())
            .thenReturn(mockedDefaultLocale)
    }

    fun mockIssuerName(
        resourceProvider: ResourceProvider,
        name: String
    ) {
        whenever(resourceProvider.getString(R.string.issuance_success_header_issuer_default_name))
            .thenReturn(name)
    }
}