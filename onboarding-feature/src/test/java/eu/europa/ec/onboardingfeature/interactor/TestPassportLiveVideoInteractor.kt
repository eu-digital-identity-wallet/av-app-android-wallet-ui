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

package eu.europa.ec.onboardingfeature.interactor

import android.content.Context
import android.graphics.Bitmap
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.businesslogic.model.ErrorType
import eu.europa.ec.onboardingfeature.controller.FaceMatchController
import eu.europa.ec.onboardingfeature.controller.FaceMatchResult
import eu.europa.ec.passportscanner.face.SdkInitStatus
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.testlogic.extension.runTest
import eu.europa.ec.testlogic.rule.CoroutineTestRule
import junit.framework.TestCase.assertEquals
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.toList
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.mockito.Mock
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.any
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

class TestPassportLiveVideoInteractor {

    @get:Rule
    val coroutineRule = CoroutineTestRule()

    @Mock
    private lateinit var faceMatchController: FaceMatchController

    @Mock
    private lateinit var resourceProvider: ResourceProvider

    @Mock
    private lateinit var logController: LogController

    @Mock
    private lateinit var context: Context

    @Mock
    private lateinit var passportFace: Bitmap

    private lateinit var interactor: PassportLiveVideoInteractor

    private lateinit var closeable: AutoCloseable

    private val mockedRetryError = "Please try again"
    private val mockedNotProcessedError = "Image could not be processed"
    private val mockedNotLiveError = "Liveness check failed"
    private val mockedNotMatchingError = "Face does not match"

    @Before
    fun before() {
        closeable = MockitoAnnotations.openMocks(this)

        interactor = PassportLiveVideoInteractorImpl(
            faceMatchController = faceMatchController,
            resourceProvider = resourceProvider,
            logController = logController
        )

        whenever(resourceProvider.getString(R.string.generic_error_retry)).thenReturn(
            mockedRetryError
        )
        whenever(resourceProvider.getString(R.string.passport_live_video_error_not_processed))
            .thenReturn(mockedNotProcessedError)
        whenever(resourceProvider.getString(R.string.passport_live_video_error_not_live))
            .thenReturn(mockedNotLiveError)
        whenever(resourceProvider.getString(R.string.passport_live_video_error_not_matching))
            .thenReturn(mockedNotMatchingError)
    }

    @After
    fun after() {
        closeable.close()
    }

    //region init

    @Test
    fun `Given SDK initialization flow completes successfully, When init is called, Then emits correct state sequence ending with Ready`() {
        coroutineRule.runTest {
            // Given
            val initFlow = flowOf(
                SdkInitStatus.NotInitialized,
                SdkInitStatus.Preparing(25),
                SdkInitStatus.Preparing(50),
                SdkInitStatus.Preparing(75),
                SdkInitStatus.Preparing(100),
                SdkInitStatus.Initializing,
                SdkInitStatus.Ready
            )
            whenever(faceMatchController.init(any())).thenReturn(initFlow)

            // When
            val results = interactor.initFaceMatchSDK(context).toList()

            // Then
            assertEquals(7, results.size)
            assert(results[0] is FaceMatchSDKPartialState.NotInitialized)
            assert(results[1] is FaceMatchSDKPartialState.Preparing)
            assertEquals(25, (results[1] as FaceMatchSDKPartialState.Preparing).progress)
            assert(results[2] is FaceMatchSDKPartialState.Preparing)
            assertEquals(50, (results[2] as FaceMatchSDKPartialState.Preparing).progress)
            assert(results[3] is FaceMatchSDKPartialState.Preparing)
            assertEquals(75, (results[3] as FaceMatchSDKPartialState.Preparing).progress)
            assert(results[4] is FaceMatchSDKPartialState.Preparing)
            assertEquals(100, (results[4] as FaceMatchSDKPartialState.Preparing).progress)
            assert(results[5] is FaceMatchSDKPartialState.Initializing)
            assert(results[6] is FaceMatchSDKPartialState.Ready)
            verify(faceMatchController, times(1)).init(any())
        }
    }

    @Test
    fun `Given SDK initialization fails, When init is called, Then emits Error state with message`() {
        coroutineRule.runTest {
            // Given
            val errorMessage = "Initialization failed"
            val initFlow = flowOf(
                SdkInitStatus.NotInitialized,
                SdkInitStatus.Preparing(10),
                SdkInitStatus.Error(errorMessage)
            )
            whenever(faceMatchController.init(any())).thenReturn(initFlow)

            // When
            val results = interactor.initFaceMatchSDK(context).toList()

            // Then
            assertEquals(3, results.size)
            assert(results[0] is FaceMatchSDKPartialState.NotInitialized)
            assert(results[1] is FaceMatchSDKPartialState.Preparing)
            assert(results[2] is FaceMatchSDKPartialState.Error)
            assertEquals(errorMessage, (results[2] as FaceMatchSDKPartialState.Error).message)
            assertEquals(ErrorType.GENERIC, (results[2] as FaceMatchSDKPartialState.Error).errorType)
        }
    }

    @Test
    fun `Given SDK initialization fails with no connection, When init called, Then emits Error state with NO_CONNECTION`() {
        coroutineRule.runTest {
            // Given
            val errorMessage = "Initialization failed: Unable to resolve host"
            val initFlow = flowOf(
                SdkInitStatus.NotInitialized,
                SdkInitStatus.Error(
                    message = errorMessage,
                    errorType = ErrorType.NO_CONNECTION
                )
            )
            whenever(faceMatchController.init(any())).thenReturn(initFlow)

            // When
            val results = interactor.initFaceMatchSDK(context).toList()

            // Then
            assertEquals(2, results.size)
            assert(results[0] is FaceMatchSDKPartialState.NotInitialized)
            assert(results[1] is FaceMatchSDKPartialState.Error)
            val errorState = results[1] as FaceMatchSDKPartialState.Error
            assertEquals(errorMessage, errorState.message)
            assertEquals(ErrorType.NO_CONNECTION, errorState.errorType)
        }
    }

    @Test
    fun `Given SDK immediately ready, When init is called, Then emits Ready state`() {
        coroutineRule.runTest {
            // Given - SDK already initialized
            val initFlow = flowOf(SdkInitStatus.Ready)
            whenever(faceMatchController.init(any())).thenReturn(initFlow)

            // When
            val results = interactor.initFaceMatchSDK(context).toList()

            // Then
            assertEquals(1, results.size)
            assert(results[0] is FaceMatchSDKPartialState.Ready)
        }
    }

    //endregion

    //region captureAndMatchFace

    @Test
    fun `Given SDK not initialized, When captureAndMatchFace is called, Then returns Failure state`() {
        coroutineRule.runTest {
            // Given - SDK not initialized, controller throws exception
            whenever(faceMatchController.captureAndMatch(any()))
                .thenThrow(IllegalStateException("SDK not initialized"))

            // When
            val result = interactor.captureAndMatchFace(passportFace)

            // Then
            assert(result is FaceMatchPartialState.Failure)
            assertEquals(mockedRetryError, (result as FaceMatchPartialState.Failure).error)
        }
    }

    @Test
    fun `Given successful face match, When captureAndMatchFace is called, Then returns Success state`() {
        coroutineRule.runTest {
            // Given
            val successResult = FaceMatchResult(
                processed = true,
                capturedIsLive = true,
                isSameSubject = true
            )
            whenever(faceMatchController.captureAndMatch(any())).thenReturn(successResult)

            // When
            val result = interactor.captureAndMatchFace(passportFace)

            // Then
            assertEquals(FaceMatchPartialState.Success, result)
        }
    }

    @Test
    fun `Given face not processed, When captureAndMatchFace is called, Then returns Failure state with not processed error`() {
        coroutineRule.runTest {
            // Given
            val failureResult = FaceMatchResult(
                processed = false,
                capturedIsLive = true,
                isSameSubject = true
            )
            whenever(faceMatchController.captureAndMatch(any())).thenReturn(failureResult)

            // When
            val result = interactor.captureAndMatchFace(passportFace)

            // Then
            assert(result is FaceMatchPartialState.Failure)
            assertEquals(mockedNotProcessedError, (result as FaceMatchPartialState.Failure).error)
        }
    }

    @Test
    fun `Given face not live, When captureAndMatchFace is called, Then returns Failure state with not live error`() {
        coroutineRule.runTest {
            // Given
            val failureResult = FaceMatchResult(
                processed = true,
                capturedIsLive = false,
                isSameSubject = true
            )
            whenever(faceMatchController.captureAndMatch(any())).thenReturn(failureResult)

            // When
            val result = interactor.captureAndMatchFace(passportFace)

            // Then
            assert(result is FaceMatchPartialState.Failure)
            assertEquals(mockedNotLiveError, (result as FaceMatchPartialState.Failure).error)
        }
    }

    @Test
    fun `Given faces do not match, When captureAndMatchFace is called, Then returns Failure state with not matching error`() {
        coroutineRule.runTest {
            // Given
            val failureResult = FaceMatchResult(
                processed = true,
                capturedIsLive = true,
                isSameSubject = false
            )
            whenever(faceMatchController.captureAndMatch(any())).thenReturn(failureResult)

            // When
            val result = interactor.captureAndMatchFace(passportFace)

            // Then
            assert(result is FaceMatchPartialState.Failure)
            assertEquals(mockedNotMatchingError, (result as FaceMatchPartialState.Failure).error)
        }
    }

    @Test
    fun `Given captureAndMatch throws IllegalStateException, When captureAndMatchFace is called, Then returns Failure state`() {
        coroutineRule.runTest {
            // Given
            whenever(faceMatchController.captureAndMatch(any()))
                .thenThrow(IllegalStateException("SDK not ready"))

            // When
            val result = interactor.captureAndMatchFace(passportFace)

            // Then
            assert(result is FaceMatchPartialState.Failure)
            assertEquals(mockedRetryError, (result as FaceMatchPartialState.Failure).error)
        }
    }
    //endregion
}
