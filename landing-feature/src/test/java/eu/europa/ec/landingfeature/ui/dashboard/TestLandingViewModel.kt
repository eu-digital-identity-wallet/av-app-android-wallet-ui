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

package eu.europa.ec.landingfeature.ui.dashboard

import eu.europa.ec.landingfeature.interactor.LandingPageInteractor
import eu.europa.ec.landingfeature.interactor.LandingPageInteractor.GetAgeCredentialPartialState
import eu.europa.ec.landingfeature.model.AgeCredentialUi
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.testlogic.extension.runFlowTest
import eu.europa.ec.testlogic.extension.runTest
import eu.europa.ec.testlogic.rule.CoroutineTestRule
import eu.europa.ec.uilogic.navigation.OnboardingScreens
import eu.europa.ec.uilogic.serializer.UiSerializer
import junit.framework.TestCase.assertEquals
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.mockito.Mock
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.whenever

class TestLandingViewModel {

    @get:Rule
    val coroutineRule = CoroutineTestRule()

    @Mock
    private lateinit var landingPageInteractor: LandingPageInteractor

    @Mock
    private lateinit var resourceProvider: ResourceProvider

    @Mock
    private lateinit var uiSerializer: UiSerializer

    private lateinit var closeable: AutoCloseable

    @Before
    fun before() {
        closeable = MockitoAnnotations.openMocks(this)
        Dispatchers.setMain(UnconfinedTestDispatcher())

        whenever(
            resourceProvider.getString(
                R.string.content_description_landing_screen_credential_card,
                AGE_THRESHOLD
            )
        ).thenReturn(CARD_LABEL_18)
        whenever(
            resourceProvider.getString(
                R.string.content_description_landing_screen_credential_card_no_age
            )
        ).thenReturn(NO_AGE_CARD_LABEL)
    }

    @After
    fun after() {
        Dispatchers.resetMain()
        closeable.close()
    }

    @Test
    fun `Init with accesses left describes the card and the remaining accesses`() = coroutineRule.runTest {
        whenever(
            resourceProvider.getString(
                R.string.content_description_landing_screen_credential_card,
                21
            )
        ).thenReturn(CARD_LABEL_21)
        whenever(
            resourceProvider.getQuantityString(
                R.plurals.landing_screen_credentials_left,
                3,
                3
            )
        ).thenReturn("3 left")
        whenever(
            resourceProvider.getQuantityString(
                R.plurals.content_description_landing_screen_credentials_left,
                3,
                3
            )
        ).thenReturn(ACCESSES_LEFT_LABEL)
        mockAgeCredential(credentialCount = 3, ageThreshold = 21)

        val viewModel = createViewModel()
        viewModel.setEvent(Event.Init(deepLinkUri = null, intentAction = null))

        val card = viewModel.viewState.value.credentialCard
        assertEquals(21, card.ageThreshold)
        assertEquals(CARD_LABEL_21, card.accessibilityLabel)
        assertEquals("3 left", card.remainingAccesses?.label)
        assertEquals(ACCESSES_LEFT_LABEL, card.remainingAccesses?.accessibilityLabel)
        assertEquals(false, card.remainingAccesses?.isDepleted)
    }

    @Test
    fun `Init with no accesses left offers adding more credentials`() = coroutineRule.runTest {
        whenever(resourceProvider.getString(R.string.landing_screen_add_credentials))
            .thenReturn("Add more")
        whenever(
            resourceProvider.getString(R.string.content_description_landing_screen_add_credentials)
        ).thenReturn(ADD_CREDENTIALS_LABEL)
        mockAgeCredential(credentialCount = 0, ageThreshold = AGE_THRESHOLD)

        val viewModel = createViewModel()
        viewModel.setEvent(Event.Init(deepLinkUri = null, intentAction = null))

        val remainingAccesses = viewModel.viewState.value.credentialCard.remainingAccesses
        assertEquals("Add more", remainingAccesses?.label)
        assertEquals(ADD_CREDENTIALS_LABEL, remainingAccesses?.accessibilityLabel)
        assertEquals(true, remainingAccesses?.isDepleted)
    }

    @Test
    fun `Init without an age threshold leaves the card without an age`() = coroutineRule.runTest {
        whenever(
            resourceProvider.getQuantityString(
                R.plurals.landing_screen_credentials_left,
                1,
                1
            )
        ).thenReturn("1 left")
        whenever(
            resourceProvider.getQuantityString(
                R.plurals.content_description_landing_screen_credentials_left,
                1,
                1
            )
        ).thenReturn("1 proof of age left")
        mockAgeCredential(credentialCount = 1, ageThreshold = null)

        val viewModel = createViewModel()
        viewModel.setEvent(Event.Init(deepLinkUri = null, intentAction = null))

        val card = viewModel.viewState.value.credentialCard
        assertEquals(null, card.ageThreshold)
        assertEquals(NO_AGE_CARD_LABEL, card.accessibilityLabel)
    }

    @Test
    fun `initial state has no age and no remaining accesses to show`() = coroutineRule.runTest {
        val card = createViewModel().viewState.value.credentialCard

        assertEquals(null, card.ageThreshold)
        assertEquals(NO_AGE_CARD_LABEL, card.accessibilityLabel)
        assertEquals(null, card.remainingAccesses)
    }

    @Test
    fun `AddCredentials with no accesses left navigates to enrollment`() = coroutineRule.runTest {
        whenever(resourceProvider.getString(R.string.landing_screen_add_credentials))
            .thenReturn("Add more")
        whenever(
            resourceProvider.getString(R.string.content_description_landing_screen_add_credentials)
        ).thenReturn(ADD_CREDENTIALS_LABEL)
        mockAgeCredential(credentialCount = 0, ageThreshold = AGE_THRESHOLD)

        val viewModel = createViewModel()
        viewModel.setEvent(Event.Init(deepLinkUri = null, intentAction = null))

        viewModel.effect.runFlowTest {
            viewModel.setEvent(Event.AddCredentials)

            val effect = awaitItem() as Effect.Navigation.SwitchScreen
            assertEquals(OnboardingScreens.Enrollment.screenRoute, effect.screenRoute)
        }
    }

    @Test
    fun `AddCredentials with accesses left goes nowhere`() = coroutineRule.runTest {
        whenever(
            resourceProvider.getQuantityString(
                R.plurals.landing_screen_credentials_left,
                3,
                3
            )
        ).thenReturn("3 left")
        whenever(
            resourceProvider.getQuantityString(
                R.plurals.content_description_landing_screen_credentials_left,
                3,
                3
            )
        ).thenReturn(ACCESSES_LEFT_LABEL)
        mockAgeCredential(credentialCount = 3, ageThreshold = AGE_THRESHOLD)

        val viewModel = createViewModel()
        viewModel.setEvent(Event.Init(deepLinkUri = null, intentAction = null))

        viewModel.effect.runFlowTest {
            viewModel.setEvent(Event.AddCredentials)

            expectNoEvents()
        }
    }

    private fun mockAgeCredential(credentialCount: Int, ageThreshold: Int?) {
        whenever(landingPageInteractor.getAgeCredential()).thenReturn(
            flowOf(
                GetAgeCredentialPartialState.Success(
                    AgeCredentialUi(
                        docId = "docId",
                        claims = emptyList(),
                        credentialCount = credentialCount,
                        ageThreshold = ageThreshold,
                    )
                )
            )
        )
    }

    private fun createViewModel() = LandingViewModel(
        landingPageInteractor = landingPageInteractor,
        resourceProvider = resourceProvider,
        uiSerializer = uiSerializer,
    )

    private companion object {
        const val AGE_THRESHOLD = 18
        const val CARD_LABEL_18 =
            "European Union proof of age, confirming that you are over 18"
        const val CARD_LABEL_21 = "European Union proof of age, confirming that you are over 21"
        const val NO_AGE_CARD_LABEL = "European Union proof of age"
        const val ACCESSES_LEFT_LABEL = "3 proofs of age left"
        const val ADD_CREDENTIALS_LABEL = "No proofs of age left. Add more."
    }
}
