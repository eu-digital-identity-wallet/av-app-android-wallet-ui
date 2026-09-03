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

package eu.europa.ec.commonfeature.ui.pin

import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.businesslogic.provider.ElapsedRealtimeClock
import eu.europa.ec.businesslogic.validator.FormValidationResult
import eu.europa.ec.commonfeature.interactor.QuickPinInteractor
import eu.europa.ec.commonfeature.interactor.QuickPinInteractorPinValidPartialState
import eu.europa.ec.commonfeature.model.PinFlow
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.testlogic.rule.CoroutineTestRule
import eu.europa.ec.uilogic.serializer.UiSerializer
import junit.framework.TestCase.assertEquals
import junit.framework.TestCase.assertNull
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import eu.europa.ec.testlogic.base.TestApplication
import org.mockito.Mock
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.any
import org.mockito.kotlin.anyVararg
import org.mockito.kotlin.eq
import org.mockito.kotlin.whenever
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The countdown ticks once a second into the field the screen renders. It must not land in the
 * announced one, or a screen reader is interrupted every tick; the lockout itself still has to be
 * announced once when it starts.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = TestApplication::class, sdk = [36])
class TestPinViewModel {

    private val testDispatcher = StandardTestDispatcher()

    @get:Rule
    val coroutineRule = CoroutineTestRule(testDispatcher)

    @Mock
    private lateinit var interactor: QuickPinInteractor

    @Mock
    private lateinit var resourceProvider: ResourceProvider

    @Mock
    private lateinit var uiSerializer: UiSerializer

    @Mock
    private lateinit var logController: LogController

    private var fakeNow: Long = 0L
    private val clock = ElapsedRealtimeClock { fakeNow }

    private lateinit var closeable: AutoCloseable

    @Before
    fun before() {
        closeable = MockitoAnnotations.openMocks(this)
        Dispatchers.setMain(testDispatcher)
        whenever(resourceProvider.getString(any())).thenReturn("")
        whenever(resourceProvider.getString(any(), anyVararg())).thenReturn("")
        whenever(resourceProvider.getString(eq(R.string.quick_pin_locked_out)))
            .thenReturn(LOCKED_OUT)
        whenever(resourceProvider.getString(eq(R.string.quick_pin_change_lockout_countdown_seconds), any()))
            .thenReturn(COUNTDOWN)
    }

    @After
    fun after() {
        Dispatchers.resetMain()
        closeable.close()
    }

    @Test
    fun `Given lockout starts, Then it is announced once and the countdown is not`() =
        coroutineRule.testScope.runTest {
            fakeNow = 0L
            whenever(interactor.validateForm(any())).thenReturn(FormValidationResult(true))
            whenever(interactor.isCurrentPinValid(any())).thenReturn(
                flowOf(
                    QuickPinInteractorPinValidPartialState.LockedOut(
                        lockoutEndTime = 30_000L,
                        attemptsUsed = 4
                    )
                )
            )

            val viewModel = PinViewModel(
                interactor = interactor,
                resourceProvider = resourceProvider,
                uiSerializer = uiSerializer,
                logController = logController,
                clock = clock,
                pinFlow = PinFlow.UPDATE,
            )

            viewModel.setEvent(Event.OnQuickPinEntered("147258"))
            runCurrent()

            // Announced once, when lockout begins.
            assertEquals(LOCKED_OUT, viewModel.viewState.value.quickPinError)

            // Every tick lands in the field that is rendered but never announced, and leaves the
            // announced one alone.
            advanceTimeBy(3_100L)
            runCurrent()
            assertEquals(COUNTDOWN, viewModel.viewState.value.lockoutMessage)
            assertEquals(LOCKED_OUT, viewModel.viewState.value.quickPinError)

            // Both are cleared when the lockout expires.
            fakeNow = 30_000L
            advanceTimeBy(1_100L)
            runCurrent()
            assertNull(viewModel.viewState.value.lockoutMessage)
            assertNull(viewModel.viewState.value.quickPinError)
        }

    private companion object {
        const val LOCKED_OUT = "Too many failed attempts."
        const val COUNTDOWN = "Try again in 28 seconds"
    }
}
