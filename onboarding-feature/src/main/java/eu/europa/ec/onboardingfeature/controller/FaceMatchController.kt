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

package eu.europa.ec.onboardingfeature.controller

import android.content.Context
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.corelogic.config.WalletCoreConfig
import eu.europa.ec.passportscanner.face.AVFaceMatchSDK
import eu.europa.ec.passportscanner.face.AVFaceMatchSdkImpl
import eu.europa.ec.passportscanner.face.FaceMatchConfig
import eu.europa.ec.passportscanner.face.SdkInitStatus
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

data class FaceMatchResult(
    val processed: Boolean,
    val capturedIsLive: Boolean,
    val isSameSubject: Boolean,
)

interface FaceMatchController {
    /**
     * Initialize the SDK. Idempotent - safe to call multiple times.
     * Returns a flow that emits SDK initialization status updates.
     *
     * @param context Android context
     * @return Flow emitting SdkInitStatus updates
     */
    fun init(context: Context): Flow<SdkInitStatus>

    /**
     * Capture and match face against reference image
     * @param faceImagePath Path to the reference face image
     * @return FaceMatchResult with matching details
     */
    suspend fun captureAndMatch(faceImagePath: String): FaceMatchResult
}

class FaceMatchControllerImpl(
    private val walletCoreConfig: WalletCoreConfig,
    private val logController: LogController,
) : FaceMatchController {

    private var faceMatchSDK: AVFaceMatchSDK? = null

    private fun convertConfig(): FaceMatchConfig {
        val coreConfig = walletCoreConfig.faceMatchConfig
        return FaceMatchConfig(
            faceDetectorModel = coreConfig.faceDetectorModel,
            embeddingExtractorModel = coreConfig.embeddingExtractorModel,
            livenessModel0 = coreConfig.livenessModel0,
            livenessModel1 = coreConfig.livenessModel1,
            livenessThreshold = coreConfig.livenessThreshold,
            matchingThreshold = coreConfig.matchingThreshold
        )
    }

    override fun init(context: Context): Flow<SdkInitStatus> {
        val sdk = getOrCreateSdk(context)
        return sdk.init(convertConfig(), context.applicationContext)
    }

    override suspend fun captureAndMatch(faceImagePath: String): FaceMatchResult {
        val sdk = faceMatchSDK ?: throw IllegalStateException("SDK not initialized")

        return suspendCancellableCoroutine { continuation ->
            sdk.captureAndMatch(faceImagePath) { result ->
                continuation.resume(
                    FaceMatchResult(
                        processed = result.processed,
                        capturedIsLive = result.capturedIsLive,
                        isSameSubject = result.isSameSubject
                    )
                )
            }
        }
    }

    private fun getOrCreateSdk(context: Context): AVFaceMatchSDK {
        return faceMatchSDK ?: AVFaceMatchSdkImpl(context.applicationContext, logController).also {
            faceMatchSDK = it
        }
    }
}
