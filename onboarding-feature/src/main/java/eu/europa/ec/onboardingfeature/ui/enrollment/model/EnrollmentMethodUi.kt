/*
 * Copyright (c) 2026 European Commission
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

package eu.europa.ec.onboardingfeature.ui.enrollment.model

import androidx.annotation.StringRes
import eu.europa.ec.onboardingfeature.ui.enrollment.EnrollmentMethod
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.uilogic.component.AppIcons
import eu.europa.ec.uilogic.component.IconDataUi

data class EnrollmentMethodUi(
    val method: EnrollmentMethod,
    val icon: IconDataUi,
    @param:StringRes val title: Int,
    @param:StringRes val description: Int,
    @param:StringRes val externalContextNotice: Int?,
)

fun EnrollmentMethod.toUi(): EnrollmentMethodUi = when (this) {
    EnrollmentMethod.NATIONAL_ID -> EnrollmentMethodUi(
        method = this,
        icon = AppIcons.NationalEID,
        title = R.string.onboarding_verification_national_id,
        description = R.string.onboarding_verification_national_id_description,
        externalContextNotice = R.string.onboarding_verification_opens_in_browser,
    )

    EnrollmentMethod.PASSPORT_ID_CARD -> EnrollmentMethodUi(
        method = this,
        icon = AppIcons.Id,
        title = R.string.onboarding_verification_passport_id_card,
        description = R.string.onboarding_verification_passport_id_card_description,
        externalContextNotice = null,
    )

    EnrollmentMethod.TOKEN_QR -> EnrollmentMethodUi(
        method = this,
        icon = AppIcons.QrScanner,
        title = R.string.onboarding_verification_token_qr,
        description = R.string.onboarding_verification_token_qr_description,
        externalContextNotice = null,
    )
}
