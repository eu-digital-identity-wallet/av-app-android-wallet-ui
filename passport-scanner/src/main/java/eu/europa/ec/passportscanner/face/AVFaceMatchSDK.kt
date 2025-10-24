/*
 * MIT License
 *
 * Copyright (c) 2025 Keyless Tech
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package eu.europa.ec.passportscanner.face

import android.content.Context
import kotlinx.coroutines.flow.Flow

/**
 * Configuration for Face Match SDK
 */
data class FaceMatchConfig(
    val faceDetectorModel: String,
    val embeddingExtractorModel: String,
    val livenessModel0: String,
    val livenessModel1: String,
    val livenessThreshold: Double,
    val matchingThreshold: Double,
)

/**
 * Represents the current status of SDK initialization
 */
sealed class SdkInitStatus {
    /**
     * SDK has not been initialized yet
     */
    data object NotInitialized : SdkInitStatus()

    /**
     * SDK is currently preparing models (downloading/extracting)
     * @param progress Progress percentage (0-100)
     */
    data class Preparing(val progress: Int) : SdkInitStatus()

    /**
     * Models prepared, SDK is now initializing
     */
    data object Initializing : SdkInitStatus()

    /**
     * SDK is fully initialized and ready to use
     */
    data object Ready : SdkInitStatus()

    /**
     * Initialization failed with an error
     * @param message Error message describing the failure
     */
    data class Error(val message: String) : SdkInitStatus()
}

/**
 * Interface for Age Verification Face Matching SDK
 * Provides face liveness detection and matching capabilities for passport verification
 *
 * Unified initialization:
 * - Call init() to get a flow of initialization status
 * - init() is idempotent - multiple calls return the same flow
 * - Flow emits progress from NotInitialized → Preparing → Initializing → Ready
 * - Calling init() after an error automatically retries
 */
interface AVFaceMatchSDK {

    /**
     * Initialize the SDK with configuration.
     * Handles both model preparation and SDK initialization internally.
     *
     * This method is idempotent:
     * - First call: starts initialization and returns flow
     * - Subsequent calls: return the same flow (shared state)
     * - Flow emits status updates: NotInitialized → Preparing(progress) → Initializing → Ready/Error
     * - Calls after error: retry initialization
     *
     * @param config Configuration containing model paths and thresholds
     * @param context Android context for accessing assets and storage
     * @return Flow emitting initialization status updates
     */
    fun init(
        config: FaceMatchConfig,
        context: Context,
    ): Flow<SdkInitStatus>

    /**
     * Capture live face and match against reference image
     * SDK must be in Ready state before calling this method
     *
     * @param referenceImagePath Path to the reference image from passport
     * @param onResult Callback with the matching result
     */
    fun captureAndMatch(referenceImagePath: String, onResult: (AVMatchResult) -> Unit)

    /**
     * Reset the SDK state
     * Returns initialization status to NotInitialized
     */
    fun reset()
}

/**
 * Result of face matching operation
 */
data class AVMatchResult(
    val processed: Boolean,
    val referenceIsValid: Boolean,
    val capturedIsLive: Boolean,
    val isSameSubject: Boolean,
    val capturedPath: String?
)