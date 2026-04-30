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
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private const val TAG = "PassportLiveVideoInteractor"

sealed class FaceMatchSDKPartialState {
    data object NotInitialized : FaceMatchSDKPartialState()
    data class Preparing(val progress: Int) : FaceMatchSDKPartialState()
    data object Initializing : FaceMatchSDKPartialState()
    data object Ready : FaceMatchSDKPartialState()
    data class Error(
        val message: String,
        val errorType: ErrorType = ErrorType.GENERIC,
    ) : FaceMatchSDKPartialState()
}

sealed class FaceMatchPartialState {
    data object Success : FaceMatchPartialState()
    data class Failure(val error: String) : FaceMatchPartialState()
}

interface PassportLiveVideoInteractor {
    fun initFaceMatchSDK(context: Context): Flow<FaceMatchSDKPartialState>
    suspend fun captureAndMatchFace(passportFace: Bitmap): FaceMatchPartialState
}

class PassportLiveVideoInteractorImpl(
    private val faceMatchController: FaceMatchController,
    private val resourceProvider: ResourceProvider,
    private val logController: LogController,
) : PassportLiveVideoInteractor {

    override fun initFaceMatchSDK(context: Context): Flow<FaceMatchSDKPartialState> {
        logController.d(TAG) { "Initializing face match SDK..." }

        return faceMatchController.init(context).map { sdkStatus ->
            when (sdkStatus) {
                is SdkInitStatus.NotInitialized -> {
                    logController.d(TAG) { "SDK not initialized" }
                    FaceMatchSDKPartialState.NotInitialized
                }

                is SdkInitStatus.Preparing -> {
                    logController.d(TAG) { "SDK preparing models: ${sdkStatus.progress}%" }
                    FaceMatchSDKPartialState.Preparing(sdkStatus.progress)
                }

                is SdkInitStatus.Initializing -> {
                    logController.d(TAG) { "SDK initializing" }
                    FaceMatchSDKPartialState.Initializing
                }

                is SdkInitStatus.Ready -> {
                    logController.i(TAG) { "SDK ready" }
                    FaceMatchSDKPartialState.Ready
                }

                is SdkInitStatus.Error -> {
                    logController.e(TAG) { "SDK error: ${sdkStatus.message}" }
                    FaceMatchSDKPartialState.Error(sdkStatus.message, sdkStatus.errorType)
                }
            }
        }
    }

    override suspend fun captureAndMatchFace(passportFace: Bitmap): FaceMatchPartialState {
        logController.d(TAG) { "Starting face capture and match" }

        val matchResult: FaceMatchResult = try {
            faceMatchController.captureAndMatch(passportFace)
        } catch (e: IllegalStateException) {
            logController.e(TAG) { "SDK not initialized when calling captureAndMatch: ${e.message}" }
            return FaceMatchPartialState.Failure(
                resourceProvider.getString(R.string.generic_error_retry)
            )
        }

        logController.d(TAG) {
            "Face match result: processed=${matchResult.processed}," +
                    " isLive=${matchResult.capturedIsLive}, isSame=${matchResult.isSameSubject}"
        }

        return if (matchResult.processed && matchResult.capturedIsLive && matchResult.isSameSubject) {
            logController.i(TAG) { "Face match successful" }
            FaceMatchPartialState.Success
        } else {
            val errorMessage = when {
                !matchResult.processed -> resourceProvider.getString(R.string.passport_live_video_error_not_processed)
                !matchResult.capturedIsLive -> resourceProvider.getString(R.string.passport_live_video_error_not_live)
                else -> resourceProvider.getString(R.string.passport_live_video_error_not_matching)
            }
            logController.w(TAG) { "Face match failed: $errorMessage" }
            FaceMatchPartialState.Failure(errorMessage)
        }
    }
}
