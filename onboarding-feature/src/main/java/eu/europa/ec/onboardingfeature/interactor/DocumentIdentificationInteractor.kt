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

@file:OptIn(ExperimentalTime::class)

package eu.europa.ec.onboardingfeature.interactor

import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import kotlinx.datetime.LocalDate
import kotlinx.datetime.TimeZone
import kotlinx.datetime.format.FormatStringsInDatetimeFormats
import kotlinx.datetime.format.byUnicodePattern
import kotlinx.datetime.periodUntil
import kotlinx.datetime.todayIn
import kotlin.time.Clock
import kotlin.time.ExperimentalTime

private const val TAG = "DocumentIdentificationInteractor"

sealed class DocumentValidationState {
    data object Success : DocumentValidationState()
    data class Failure(val error: String) : DocumentValidationState()
}

interface DocumentIdentificationInteractor {
    fun validateDocument(dateOfBirth: String, expiryDate: String): DocumentValidationState
}

class DocumentIdentificationInteractorImpl(
    private val resourceProvider: ResourceProvider,
    private val logController: LogController,
    private val clock: Clock = Clock.System,
) : DocumentIdentificationInteractor {

    private val genericErrorMsg
        get() = resourceProvider.genericErrorMessage()

    @OptIn(FormatStringsInDatetimeFormats::class)
    override fun validateDocument(
        dateOfBirth: String,
        expiryDate: String,
    ): DocumentValidationState {
        logController.d(TAG) { "Validating document" }

        return try {
            val today = clock.todayIn(TimeZone.currentSystemDefault())

            // Parse dates - try multiple formats
            val dateFormatter = LocalDate.Format { byUnicodePattern("MM/dd/yyyy") }
            val dobDate = LocalDate.parse(dateOfBirth, dateFormatter)
            val expiry = LocalDate.parse(expiryDate, dateFormatter)

            // Check if document is expired
            if (expiry < today) {
                val errorMessage =
                    resourceProvider.getString(R.string.passport_validation_error_expired)
                logController.w(TAG) { "Document validation failed: expired" }
                return DocumentValidationState.Failure(errorMessage)
            }

            // Check if user is at least 18 years old
            val age = dobDate.periodUntil(today).years
            if (age < 18) {
                val errorMessage =
                    resourceProvider.getString(R.string.passport_validation_error_underage)
                logController.w(TAG) { "Document validation failed: user is younger" }
                return DocumentValidationState.Failure(errorMessage)
            }

            logController.d(TAG) { "Document validation successful - user meets age requirement" }
            DocumentValidationState.Success
        } catch (e: Exception) {
            logController.e(TAG) { "Error parsing document dates: ${e.message}" }
            DocumentValidationState.Failure(genericErrorMsg)
        }
    }
}
