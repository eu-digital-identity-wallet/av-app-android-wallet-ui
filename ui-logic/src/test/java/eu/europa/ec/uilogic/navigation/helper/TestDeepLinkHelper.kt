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

package eu.europa.ec.uilogic.navigation.helper

import android.net.Uri
import eu.europa.ec.testlogic.base.TestApplication
import eu.europa.ec.uilogic.navigation.helper.DeepLinkType.CREDENTIAL_OFFER
import eu.europa.ec.uilogic.navigation.helper.DeepLinkType.OPENID4VP
import junit.framework.TestCase.assertEquals
import junit.framework.TestCase.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(application = TestApplication::class, sdk = [36])
class TestDeepLinkHelper {

    @Test
    fun `hasDeepLink accepts a spec credential offer with an empty host`() {
        assertEquals(CREDENTIAL_OFFER, typeOf("openid-credential-offer://?credential_offer=%7B%7D"))
    }

    @Test
    fun `hasDeepLink accepts a credential offer on the legacy credential_offer host`() {
        assertEquals(
            CREDENTIAL_OFFER,
            typeOf("openid-credential-offer://credential_offer?credential_offer=%7B%7D")
        )
    }

    @Test
    fun `hasDeepLink matches the legacy credential_offer host case-insensitively`() {
        assertEquals(
            CREDENTIAL_OFFER,
            typeOf("openid-credential-offer://CREDENTIAL_OFFER?credential_offer=%7B%7D")
        )
    }

    @Test
    fun `hasDeepLink accepts a credential offer passed by reference`() {
        assertEquals(
            CREDENTIAL_OFFER,
            typeOf("openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer")
        )
    }

    @Test
    fun `hasDeepLink rejects a credential offer on an unknown host`() {
        assertNull(hasDeepLink(Uri.parse("openid-credential-offer://evil?credential_offer=%7B%7D")))
    }

    @Test
    fun `hasDeepLink rejects a credential offer without an offer parameter`() {
        assertNull(hasDeepLink(Uri.parse("openid-credential-offer://?foo=bar")))
        assertNull(hasDeepLink(Uri.parse("openid-credential-offer://?credential_offer=")))
    }

    @Test
    fun `hasDeepLink rejects an opaque credential offer uri`() {
        assertNull(hasDeepLink(Uri.parse("openid-credential-offer:credential_offer=%7B%7D")))
    }

    @Test
    fun `hasDeepLink keeps presentation links untouched`() {
        assertEquals(OPENID4VP, typeOf("openid4vp://authorize?request_uri=https%3A%2F%2Fverifier.example"))
    }

    private fun typeOf(link: String): DeepLinkType? = hasDeepLink(Uri.parse(link))?.type
}
