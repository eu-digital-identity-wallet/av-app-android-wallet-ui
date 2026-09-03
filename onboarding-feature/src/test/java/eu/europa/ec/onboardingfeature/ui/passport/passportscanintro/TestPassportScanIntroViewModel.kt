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


package eu.europa.ec.onboardingfeature.ui.passport.passportscanintro

import android.content.Context
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.onboardingfeature.interactor.PassportScanIntroInteractor
import eu.europa.ec.passportscanner.face.SdkInitStatus
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.testlogic.extension.runFlowTest
import eu.europa.ec.testlogic.extension.runTest
import eu.europa.ec.testlogic.rule.CoroutineTestRule
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.mockito.Mock
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.any
import org.mockito.kotlin.whenever

class TestPassportScanIntroViewModel {

    @get:Rule
    val coroutineRule = CoroutineTestRule()

    @Mock
    private lateinit var logController: LogController

    @Mock
    private lateinit var interactor: PassportScanIntroInteractor

    @Mock
    private lateinit var resourceProvider: ResourceProvider

    @Mock
    private lateinit var context: Context

    private lateinit var closeable: AutoCloseable

    @Before
    fun before() {
        closeable = MockitoAnnotations.openMocks(this)
        Dispatchers.setMain(UnconfinedTestDispatcher())

        whenever(context.applicationContext).thenReturn(context)
        listOf(25, 50, 75, 100).forEach { step ->
            whenever(
                resourceProvider.getString(
                    R.string.passport_scan_intro_download_progress_announcement,
                    step
                )
            ).thenReturn("Downloading $step%")
        }
        whenever(
            resourceProvider.getString(R.string.passport_scan_intro_download_preparing_announcement)
        ).thenReturn(PREPARING_ANNOUNCEMENT)
    }

    @After
    fun after() {
        Dispatchers.resetMain()
        closeable.close()
    }

    @Test
    fun `download progress is announced only when it reaches the next 25 percent step`() =
        coroutineRule.runTest {
            val statuses = MutableSharedFlow<SdkInitStatus>()
            whenever(interactor.initFaceMatchSDK(any())).thenReturn(statuses)
            val viewModel = createViewModel()

            viewModel.setEvent(Event.OnDownloadClicked(context))
            assertEquals("", viewModel.viewState.value.downloadStatusAnnouncement)

            statuses.emit(SdkInitStatus.Preparing(10))
            assertEquals("", viewModel.viewState.value.downloadStatusAnnouncement)

            statuses.emit(SdkInitStatus.Preparing(30))
            assertEquals("Downloading 25%", viewModel.viewState.value.downloadStatusAnnouncement)

            statuses.emit(SdkInitStatus.Preparing(49))
            assertEquals("Downloading 25%", viewModel.viewState.value.downloadStatusAnnouncement)

            statuses.emit(SdkInitStatus.Preparing(75))
            assertEquals("Downloading 75%", viewModel.viewState.value.downloadStatusAnnouncement)
            assertEquals(75, viewModel.viewState.value.downloadProgress)
        }

    @Test
    fun `initializing announces that the download completed`() = coroutineRule.runTest {
        whenever(interactor.initFaceMatchSDK(any())).thenReturn(
            flowOf(SdkInitStatus.Preparing(50), SdkInitStatus.Initializing)
        )
        val viewModel = createViewModel()

        viewModel.setEvent(Event.OnDownloadClicked(context))

        val state = viewModel.viewState.value
        assertEquals(SdkReadiness.Downloading, state.sdkReadiness)
        assertEquals(100, state.downloadProgress)
        assertEquals(PREPARING_ANNOUNCEMENT, state.downloadStatusAnnouncement)
    }

    @Test
    fun `ready moves focus to the Start button`() = coroutineRule.runTest {
        whenever(interactor.initFaceMatchSDK(any())).thenReturn(
            flowOf(SdkInitStatus.Preparing(50), SdkInitStatus.Initializing, SdkInitStatus.Ready)
        )
        val viewModel = createViewModel()

        viewModel.effect.runFlowTest {
            viewModel.setEvent(Event.OnDownloadClicked(context))

            assertEquals(Effect.FocusStartButton, awaitItem())
            assertEquals(SdkReadiness.Ready, viewModel.viewState.value.sdkReadiness)
        }
    }

    @Test
    fun `error clears the download announcement`() = coroutineRule.runTest {
        whenever(interactor.initFaceMatchSDK(any())).thenReturn(
            flowOf(SdkInitStatus.Preparing(50), SdkInitStatus.Error("failed"))
        )
        val viewModel = createViewModel()

        viewModel.setEvent(Event.OnDownloadClicked(context))

        val state = viewModel.viewState.value
        assertEquals(SdkReadiness.NotReady, state.sdkReadiness)
        assertEquals("", state.downloadStatusAnnouncement)
    }

    private fun createViewModel() = PassportScanIntroViewModel(
        logController = logController,
        passportScanIntroInteractor = interactor,
        resourceProvider = resourceProvider,
    )

    private companion object {
        const val PREPARING_ANNOUNCEMENT = "Download complete"
    }
}
