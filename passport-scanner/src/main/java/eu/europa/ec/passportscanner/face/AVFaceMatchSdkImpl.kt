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
import android.content.Intent
import eu.europa.ec.businesslogic.controller.log.LogController
import kl.open.fmandroid.NativeBridge
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.File

/**
 * Implementation of AVFaceMatchSDK for passport face verification
 * Integrates with native face matching library for liveness detection and face comparison
 */
class AVFaceMatchSdkImpl(
    private val context: Context,
    private val logController: LogController,
) : AVFaceMatchSDK {

    private val sdkScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val modelDownloader = ModelDownloader(context, logController)
    private var modelsPrepared = false
    private var sdkInitialized = false
    private val embeddingOutputFilename = "embedding.onnx"

    private val _initStatus = MutableStateFlow<SdkInitStatus>(SdkInitStatus.NotInitialized)
    private val initStatusFlow: StateFlow<SdkInitStatus> = _initStatus.asStateFlow()

    companion object {
        private const val TAG = "AVFaceMatchSdk"

        init {
            System.loadLibrary("avfacelib") // Load the native library
        }
    }

    override fun init(
        config: FaceMatchConfig,
        context: Context,
    ): Flow<SdkInitStatus> {
        // Check if already initialized or in progress
        when (_initStatus.value) {
            is SdkInitStatus.Ready -> {
                logController.d(TAG) { "init: SDK already initialized, returning existing flow" }
                return initStatusFlow
            }

            is SdkInitStatus.Preparing, is SdkInitStatus.Initializing -> {
                logController.d(TAG) { "init: Initialization already in progress, returning existing flow" }
                return initStatusFlow
            }

            is SdkInitStatus.Error, is SdkInitStatus.NotInitialized -> {
                // Continue with initialization
                logController.d(TAG) { "init: Starting SDK initialization" }
            }
        }

        // Launch initialization in background
        sdkScope.launch {
            performInitialization(config, context)
        }

        return initStatusFlow
    }

    private suspend fun performInitialization(config: FaceMatchConfig, context: Context) {
        val modelBasePath = context.filesDir.absolutePath

        try {
            // Prepare models if not already prepared
            if (!modelsPrepared) {
                logController.d(TAG) { "init: Preparing models..." }

                // Prepare small models instantly (no progress updates)
                modelDownloader.prepareModel(config.livenessModel0, modelBasePath)
                    ?: return failWithError("Failed to prepare liveness model 0")

                modelDownloader.prepareModel(config.livenessModel1, modelBasePath)
                    ?: return failWithError("Failed to prepare liveness model 1")

                modelDownloader.prepareModel(config.faceDetectorModel, modelBasePath)
                    ?: return failWithError("Failed to prepare face detector model")

                // Embedding model might be a URL - only this shows progress
                val embeddingResult = if (config.embeddingExtractorModel.startsWith("http://") ||
                    config.embeddingExtractorModel.startsWith("https://")
                ) {
                    modelDownloader.prepareModel(
                        config.embeddingExtractorModel,
                        modelBasePath,
                        embeddingOutputFilename
                    ) { progress ->
                        _initStatus.value = SdkInitStatus.Preparing(progress)
                    }
                } else {
                    modelDownloader.prepareModel(config.embeddingExtractorModel, modelBasePath)
                }

                if (embeddingResult == null) {
                    return failWithError("Failed to prepare embedding extractor model")
                }

                modelsPrepared = true
                logController.d(TAG) { "init: Model preparation succeeded" }
            }

            // Initialize native SDK
            _initStatus.value = SdkInitStatus.Initializing
            logController.d(TAG) { "init: Initializing native SDK..." }

            // Build config JSON from FaceMatchConfig
            val configJson = JSONObject().apply {
                put("face_detector_model", config.faceDetectorModel)
                put("liveness_model0", config.livenessModel0)
                put("liveness_model1", config.livenessModel1)
                put("liveness_threshold", config.livenessThreshold)
                put("matching_threshold", config.matchingThreshold)

                // Use local filename for embedding model if it was downloaded from URL
                if (config.embeddingExtractorModel.startsWith("http://") ||
                    config.embeddingExtractorModel.startsWith("https://")
                ) {
                    put("embedding_extractor_model", embeddingOutputFilename)
                } else {
                    put("embedding_extractor_model", config.embeddingExtractorModel)
                }
            }

            logController.d(TAG) { "init: Calling native initialization..." }
            val result = NativeBridge.safeInit(configJson.toString(), modelBasePath)
            logController.d(TAG) { "init: Native initialization result: $result" }

            if (result) {
                sdkInitialized = true
                _initStatus.value = SdkInitStatus.Ready
                logController.i(TAG) { "init: SDK initialization completed successfully" }
            } else {
                failWithError("Native SDK initialization failed. Check that all model files are valid and compatible.")
            }
        } catch (e: Exception) {
            logController.e(TAG) { "init: Exception during initialization: ${e.message}" }
            failWithError("Initialization failed: ${e.message}")
        }
    }

    private fun failWithError(message: String) {
        _initStatus.value = SdkInitStatus.Error(message)
    }

    override fun captureAndMatch(referenceImagePath: String, onResult: (AVMatchResult) -> Unit) {
        logController.d(TAG) { "captureAndMatch: Starting with reference image: $referenceImagePath" }

        // Validate reference image path
        if (referenceImagePath.isEmpty() || !File(referenceImagePath).exists()) {
            logController.e(TAG) { "captureAndMatch: Invalid reference image path: $referenceImagePath" }
            onResult(
                AVMatchResult(
                    processed = true,
                    referenceIsValid = false,
                    capturedIsLive = false,
                    isSameSubject = false,
                    capturedPath = null
                )
            )
            return
        }

        logController.d(TAG) { "captureAndMatch: Processing reference image..." }

        try {
            // Process reference image first
            val originalResult = NativeBridge.safeProcess(referenceImagePath, true)
            logController.d(TAG) { "captureAndMatch: Reference processing result - embeddingExtracted: ${originalResult.embeddingExtracted}, faceDetected: ${originalResult.faceDetected}" }

            val referenceResult = AVProcessResult(
                livenessChecked = originalResult.livenessChecked,
                isLive = originalResult.isLive,
                faceDetected = originalResult.faceDetected,
                embeddingExtracted = originalResult.embeddingExtracted,
                embedding = originalResult.embedding
            )

            if (!referenceResult.embeddingExtracted) {
                logController.e(TAG) { "captureAndMatch: Failed to extract embedding from reference image" }
                // Fail fast if reference image is invalid
                onResult(
                    AVMatchResult(
                        processed = true,
                        referenceIsValid = false,
                        capturedIsLive = false,
                        isSameSubject = false,
                        capturedPath = null
                    )
                )
                return
            }

            logController.d(TAG) { "captureAndMatch: Reference image processed successfully, embedding size: ${referenceResult.embedding.size}" }

            // Initialize decision maker for multiple samples
            val decisor = AVDecisor(numSamples = 3)
            logController.d(TAG) { "captureAndMatch: Created decisor with ${decisor.getSampleCount()}/${3} samples" }

            // Set up callback holder for camera activity
            AVCameraCallbackHolder.referenceResult = referenceResult
            AVCameraCallbackHolder.decisor = decisor
            AVCameraCallbackHolder.onFinalResult = { result ->
                logController.d(TAG) { "captureAndMatch: Final callback triggered with result: $result" }
                onResult(result)
            }

            logController.d(TAG) { "captureAndMatch: Callback holder setup complete, ready: ${AVCameraCallbackHolder.isReady()}" }

            // Start camera activity for live capture
            logController.d(TAG) { "captureAndMatch: Starting CameraActivity..." }
            val intent = Intent(context, kl.open.fmandroid.CameraActivity::class.java)
            context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            logController.d(TAG) { "captureAndMatch: CameraActivity started" }

        } catch (e: Exception) {
            logController.e(TAG) { "captureAndMatch: Exception occurred: ${e.message}" }
            onResult(
                AVMatchResult(
                    processed = false,
                    referenceIsValid = false,
                    capturedIsLive = false,
                    isSameSubject = false,
                    capturedPath = null
                )
            )
        }
    }

    override fun reset() {
        logController.d(TAG) { "reset: Resetting SDK state" }
        AVCameraCallbackHolder.reset()
        NativeBridge.jni_release()
        sdkInitialized = false
        _initStatus.value = SdkInitStatus.NotInitialized
        // Note: modelsPrepared stays true as models are still in storage
        logController.d(TAG) { "reset: SDK reset complete" }
    }

    /**
     * Get SDK version information
     * @return Version string from native library
     */
    fun getVersion(): String {
        return try {
            NativeBridge.jni_getVersion()
        } catch (e: Exception) {
            "Unknown"
        }
    }

    /**
     * Match two face embeddings directly
     * @param embedding1 First face embedding
     * @param embedding2 Second face embedding
     * @return true if embeddings match (same subject)
     */
    fun matchEmbeddings(embedding1: FloatArray, embedding2: FloatArray): Boolean {
        return NativeBridge.safeMatch(embedding1, embedding2)
    }

    /**
     * Test method to process two images directly without camera
     * @param referenceImagePath Path to reference image (from passport)
     * @param capturedImagePath Path to captured image (selfie)
     * @return AVMatchResult with comparison results
     */
    fun testDirectMatch(referenceImagePath: String, capturedImagePath: String): AVMatchResult {
        // Validate paths
        if (referenceImagePath.isEmpty() || !File(referenceImagePath).exists()) {
            return AVMatchResult(
                processed = true,
                referenceIsValid = false,
                capturedIsLive = false,
                isSameSubject = false,
                capturedPath = null
            )
        }

        if (capturedImagePath.isEmpty() || !File(capturedImagePath).exists()) {
            return AVMatchResult(
                processed = true,
                referenceIsValid = true,
                capturedIsLive = false,
                isSameSubject = false,
                capturedPath = null
            )
        }

        try {
            // Process reference image
            val referenceResult = NativeBridge.jni_process(referenceImagePath, true)
            if (!referenceResult.embeddingExtracted) {
                return AVMatchResult(
                    processed = true,
                    referenceIsValid = false,
                    capturedIsLive = false,
                    isSameSubject = false,
                    capturedPath = null
                )
            }

            // Process captured image
            val capturedResult = NativeBridge.jni_process(capturedImagePath, false)
            if (!capturedResult.embeddingExtracted) {
                return AVMatchResult(
                    processed = true,
                    referenceIsValid = true,
                    capturedIsLive = false,
                    isSameSubject = false,
                    capturedPath = capturedImagePath
                )
            }

            // Match embeddings
            val isSameSubject = matchEmbeddings(referenceResult.embedding, capturedResult.embedding)

            return AVMatchResult(
                processed = true,
                referenceIsValid = true,
                capturedIsLive = capturedResult.isLive,
                isSameSubject = isSameSubject,
                capturedPath = capturedImagePath
            )

        } catch (e: Exception) {
            logController.e(TAG) { "Error in testDirectMatch: ${e.message}" }
            return AVMatchResult(
                processed = false,
                referenceIsValid = false,
                capturedIsLive = false,
                isSameSubject = false,
                capturedPath = null
            )
        }
    }
}
