/*
 * Copyright (c) 2025 European Commission
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

package eu.europa.ec.commonfeature.util

object TestTag {

    object PinScreen {
        const val TITLE = "pin_screen_title"
        const val BUTTON = "pin_screen_button"
    }

    object SuccessScreen {
        const val PRIMARY_BUTTON = "success_screen_primary_button"
        const val SECONDARY_BUTTON = "success_screen_secondary_button"
    }

    object DocumentSuccessScreen {
        const val CONTENT_HEADER_DESCRIPTION = "document_success_screen_content_header_description"
        const val BUTTON = "document_success_screen_button"

        fun successDocument(index: Int) = "document_success_screen_document_$index"
    }

    object RequestScreen {
        const val CONTENT_HEADER_DESCRIPTION = "request_screen_content_header_description"
        const val BUTTON = "request_screen_button"

        fun requestedDocument(index: Int) = "request_screen_requested_document_$index"
    }

    object BiometricScreen {
        const val PIN_TEXT = "biometric_screen_pin_text"
        const val PIN_TITLE = "biometric_screen_title"
    }

    object QrScanScreen {
        const val CAMERA_AREA = "qr_scan_screen_camera_area"
    }
}