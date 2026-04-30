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
import android.graphics.Bitmap
import eu.europa.ec.corelogic.config.WalletCoreConfig
import eu.europa.ec.passportscanner.face.AVFaceMatchSDK
import eu.europa.ec.passportscanner.face.FaceMatchConfig
import eu.europa.ec.passportscanner.face.FaceMatchModelSource
import eu.europa.ec.passportscanner.face.SdkInitStatus
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.suspendCancellableCoroutine
import java.io.ByteArrayOutputStream
import kotlin.coroutines.resume
import eu.europa.ec.corelogic.config.FaceMatchModelSource as CoreFaceMatchModelSource

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
     * Cancel any ongoing SDK initialization (model download/preparation).
     */
    fun cancelInit()

    /**
     * Capture and match face against the in-memory reference bitmap.
     * The bitmap is encoded to PNG bytes in memory and passed directly to the native layer —
     * nothing is written to disk.
     *
     * @param passportFace Reference face bitmap from the passport NFC chip
     * @return FaceMatchResult with matching details
     */
    suspend fun captureAndMatch(passportFace: Bitmap): FaceMatchResult
}

class FaceMatchControllerImpl(
    private val walletCoreConfig: WalletCoreConfig,
    private val faceMatchSDK: AVFaceMatchSDK,
) : FaceMatchController {

    private fun convertConfig(): FaceMatchConfig {
        val coreConfig = walletCoreConfig.faceMatchConfig
        return FaceMatchConfig(
            faceDetectorModel = coreConfig.faceDetectorModel.toScannerSource(),
            embeddingExtractorModel = coreConfig.embeddingExtractorModel.toScannerSource(),
            livenessModel0 = coreConfig.livenessModel0.toScannerSource(),
            livenessModel1 = coreConfig.livenessModel1.toScannerSource(),
            livenessThreshold = coreConfig.livenessThreshold,
            matchingThreshold = coreConfig.matchingThreshold,
        )
    }

    private fun CoreFaceMatchModelSource.toScannerSource(): FaceMatchModelSource = when (this) {
        is CoreFaceMatchModelSource.Asset -> FaceMatchModelSource.Asset(filename)
        is CoreFaceMatchModelSource.Remote -> FaceMatchModelSource.Remote(url, sha256Hex)
    }

    override fun init(context: Context): Flow<SdkInitStatus> {
        return faceMatchSDK.init(convertConfig(), context.applicationContext)
    }

    override fun cancelInit() {
        faceMatchSDK.cancelInit()
    }

    override suspend fun captureAndMatch(passportFace: Bitmap): FaceMatchResult {
        val pngBytes = ByteArrayOutputStream().also { buf ->
            passportFace.compress(Bitmap.CompressFormat.PNG, 100, buf)
        }.toByteArray()
        return suspendCancellableCoroutine { continuation ->
            faceMatchSDK.captureAndMatch(pngBytes) { result ->
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
}
