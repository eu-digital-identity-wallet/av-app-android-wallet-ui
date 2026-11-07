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

package eu.europa.ec.commonfeature.ui.qr_scan

import android.content.Context
import app.cash.turbine.test
import eu.europa.ec.businesslogic.validator.FormValidationResult
import eu.europa.ec.businesslogic.validator.FormValidator
import eu.europa.ec.commonfeature.config.QrScanFlow
import eu.europa.ec.commonfeature.config.QrScanUiConfig
import eu.europa.ec.commonfeature.ui.qr_scan.Effect.Navigation.SwitchScreen
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.testlogic.base.TestApplication
import eu.europa.ec.testlogic.rule.CoroutineTestRule
import eu.europa.ec.uilogic.navigation.IssuanceScreens
import eu.europa.ec.uilogic.navigation.PresentationScreens
import eu.europa.ec.uilogic.serializer.UiSerializerImpl
import junit.framework.TestCase.assertEquals
import junit.framework.TestCase.assertFalse
import junit.framework.TestCase.assertTrue
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.koin.core.context.startKoin
import org.koin.core.context.stopKoin
import org.mockito.Mock
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.any
import org.mockito.kotlin.whenever
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(application = TestApplication::class, sdk = [36])
class TestQrScanViewModel {

    @get:Rule
    val coroutineRule = CoroutineTestRule(UnconfinedTestDispatcher())

    @Mock
    private lateinit var formValidator: FormValidator

    @Mock
    private lateinit var resourceProvider: ResourceProvider

    @Mock
    private lateinit var context: Context

    private val uiSerializer = UiSerializerImpl()

    private lateinit var closeable: AutoCloseable

    @Before
    fun before() {
        closeable = MockitoAnnotations.openMocks(this)
        startKoin { }
        whenever(resourceProvider.getString(any())).thenReturn("")
    }

    @After
    fun after() {
        stopKoin()
        closeable.close()
    }

    @Test
    fun `scanning a credential offer from the presentation scanner opens the document offer`() =
        coroutineRule.testScope.runTest {
            whenever(formValidator.validateForm(any())).thenReturn(FormValidationResult(true))
            val viewModel = viewModel(QrScanFlow.Presentation)

            viewModel.effect.test {
                viewModel.setEvent(Event.OnQrScanned(context, CREDENTIAL_OFFER))

                assertRoute(IssuanceScreens.DocumentOffer.screenName, awaitItem())
            }
        }

    @Test
    fun `scanning a presentation request from the presentation scanner opens the presentation request`() =
        coroutineRule.testScope.runTest {
            whenever(formValidator.validateForm(any())).thenReturn(FormValidationResult(true))
            val viewModel = viewModel(QrScanFlow.Presentation)

            viewModel.effect.test {
                viewModel.setEvent(Event.OnQrScanned(context, PRESENTATION_REQUEST))

                assertRoute(PresentationScreens.PresentationRequest.screenName, awaitItem())
            }
        }

    @Test
    fun `scanning a credential offer on an unknown host from the presentation scanner counts as a failed scan`() =
        coroutineRule.testScope.runTest {
            whenever(formValidator.validateForm(any())).thenReturn(FormValidationResult(true))
            val viewModel = viewModel(QrScanFlow.Presentation)

            viewModel.effect.test {
                viewModel.setEvent(Event.OnQrScanned(context, OFFER_ON_UNKNOWN_HOST))

                expectNoEvents()
            }
            with(viewModel.viewState.value) {
                assertEquals(1, failedScanAttempts)
                assertFalse(finishedScanning)
            }
        }

    private fun viewModel(flow: QrScanFlow) = QrScanViewModel(
        formValidator = formValidator,
        uiSerializer = uiSerializer,
        resourceProvider = resourceProvider,
        qrScannedConfig = uiSerializer.toBase64(
            QrScanUiConfig(title = "", subTitle = "", qrScanFlow = flow),
            QrScanUiConfig.Parser
        ).orEmpty(),
    )

    private fun assertRoute(expectedScreen: String, effect: Effect) {
        val route = (effect as SwitchScreen).screenRoute
        assertTrue(route, route.startsWith(expectedScreen))
    }

    private companion object {
        const val CREDENTIAL_OFFER = "openid-credential-offer://?credential_offer=%7B%7D"
        const val OFFER_ON_UNKNOWN_HOST = "openid-credential-offer://evil?credential_offer=%7B%7D"
        const val PRESENTATION_REQUEST = "openid4vp://authorize?request_uri=https%3A%2F%2Fverifier.example"
    }
}
