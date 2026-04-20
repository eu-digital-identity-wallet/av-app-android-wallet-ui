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
package kl.open.fmandroid

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.os.Bundle
import android.util.Size
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.passportscanner.face.AVCameraCallbackHolder
import eu.europa.ec.passportscanner.face.AVMatchResult
import org.koin.android.ext.android.inject
import java.io.File

class CameraActivity : AppCompatActivity() {

    private val logController: LogController by inject()
    private val nativeBridge :NativeBridge by inject()
    private val avCameraCallbackHolder: AVCameraCallbackHolder by inject()

    private lateinit var imageCapture: ImageCapture
    private lateinit var previewView: PreviewView

    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted: Boolean ->
        if (isGranted) {
            startCamera()
        } else {
            Toast.makeText(this, "Camera permission denied", Toast.LENGTH_SHORT).show()
            avCameraCallbackHolder.triggerCallback(MatchResult.error())
            finish()
        }
    }

    private fun imageProxyToBitmap(imageProxy: ImageProxy): Bitmap? {
        val planeProxy = imageProxy.planes[0]
        val buffer = planeProxy.buffer
        val bytes = ByteArray(buffer.remaining())
        buffer.get(bytes)
        return BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        logController.d("CameraActivity") { "onCreate: Starting camera activity" }

        previewView = PreviewView(this)
        previewView.scaleX = -1f // Mirror the preview
        setContentView(previewView)

        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
            == PackageManager.PERMISSION_GRANTED
        ) {
            startCamera()
        } else {
            requestPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    private fun startCamera() {
        logController.d("CameraActivity") { "startCamera: Initializing camera" }
        val cameraProviderFuture = ProcessCameraProvider.getInstance(this)

        cameraProviderFuture.addListener({
            val cameraProvider = cameraProviderFuture.get()

            val preview = Preview.Builder().build().also {
                it.surfaceProvider = previewView.surfaceProvider
            }

            val resolutionSelector = ResolutionSelector.Builder()
                .setResolutionStrategy(
                    ResolutionStrategy(
                        Size(1280, 720),
                        ResolutionStrategy.FALLBACK_RULE_CLOSEST_LOWER_THEN_HIGHER
                    )
                )
                .build()

            imageCapture = ImageCapture.Builder()
                .setResolutionSelector(resolutionSelector)
                .build()

            val cameraSelector = CameraSelector.DEFAULT_FRONT_CAMERA

            cameraProvider.unbindAll()
            cameraProvider.bindToLifecycle(this, cameraSelector, preview, imageCapture)

            logController.d("CameraActivity") { "startCamera: Camera bound, starting capture" }
            // Start the first frame capture
            captureFrame()

        }, ContextCompat.getMainExecutor(this))
    }

    private fun captureFrame() {
        logController.d("CameraActivity") { "captureFrame: Capturing frame" }
        val finalFile =
            File(cacheDir, "captured_frame_${System.currentTimeMillis()}.png")

        val imageCaptureCallback = object : ImageCapture.OnImageCapturedCallback() {
            override fun onCaptureSuccess(imageProxy: ImageProxy) {
                logController.d("CameraActivity") { "captureFrame: Image captured successfully" }
                // Convert raw ImageProxy to Bitmap
                val bitmap = imageProxyToBitmap(imageProxy)
                // Read the correct rotation from the ImageProxy metadata
                val rotationDegrees = imageProxy.imageInfo.rotationDegrees.toFloat()
                // Close the ImageProxy early to free camera resources
                imageProxy.close()

                // If we got a valid Bitmap, rotate and save as PNG
                if (bitmap != null) {
                    // Rotate the bitmap to upright orientation
                    val matrix =
                        Matrix().apply { if (rotationDegrees != 0f) postRotate(rotationDegrees) }
                    val rotatedBitmap = Bitmap.createBitmap(
                        bitmap, 0, 0, bitmap.width, bitmap.height, matrix, true
                    )

                    // Save as lossless PNG
                    finalFile.outputStream().use { out ->
                        rotatedBitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
                    }

                    logController.d("CameraActivity") { "captureFrame: Image saved to ${finalFile.absolutePath}" }
                    // Pass the saved file path into the processing pipeline
                    processCapturedImage(finalFile.absolutePath)
                } else {
                    logController.e("CameraActivity") {
                        "captureFrame: Failed to convert imageProxy to bitmap"
                    }
                    // On error, report a failure result and clean up
                    avCameraCallbackHolder.triggerCallback(MatchResult.error())
                    finish()
                }
            }

            override fun onError(exception: ImageCaptureException) {
                logController.e("CameraActivity", exception) {
                    "captureFrame: Image capture failed"
                }
                avCameraCallbackHolder.triggerCallback(MatchResult.error())
                finish()
            }
        }

        imageCapture.takePicture(
            ContextCompat.getMainExecutor(this),
            imageCaptureCallback
        )
    }

    fun processCapturedImage(imagePath: String) {
        logController.d("CameraActivity") { "processCapturedImage: Processing $imagePath" }
        try {
            val capturedResult = nativeBridge.safeProcess(imagePath, false)
            logController.d("CameraActivity") {
                "processCapturedImage: Face detected: ${capturedResult.faceDetected}, " +
                        "Live: ${capturedResult.isLive}"
            }

            if (capturedResult.faceDetected && capturedResult.embeddingExtracted) {
                val referenceEmbedding = avCameraCallbackHolder.referenceResult?.embedding
                if (referenceEmbedding != null) {
                    val isSameSubject =
                        nativeBridge.safeMatch(referenceEmbedding, capturedResult.embedding)

                    logController.d("CameraActivity") {
                        "processCapturedImage: Same subject: $isSameSubject"
                    }

                    avCameraCallbackHolder.decisor?.addResult(isSameSubject)

                    if (avCameraCallbackHolder.decisor?.hasEnoughSamples() == true) {
                        val finalDecision =
                            avCameraCallbackHolder.decisor?.getFinalDecision() ?: false
                        logController.d("CameraActivity") {
                            "processCapturedImage: Final decision: $finalDecision"
                        }
                        finishCapture(imagePath, capturedResult.isLive, finalDecision)
                    } else {
                        logController.d("CameraActivity") {
                            "processCapturedImage: Need more samples, capturing next frame"
                        }
                        captureFrame()
                    }
                } else {
                    logController.e("CameraActivity") {
                        "processCapturedImage: No reference embedding available"
                    }
                    avCameraCallbackHolder.triggerCallback(MatchResult.error())
                    finish()
                }
            } else {
                logController.d("CameraActivity") {
                    "processCapturedImage: No face detected, retrying"
                }
                // No face detected, just retry another capture
                captureFrame()
            }
        } catch (e: Exception) {
            logController.e("CameraActivity",e) {
                "processCapturedImage: Exception during processing"
            }
            avCameraCallbackHolder.triggerCallback(MatchResult.error())
            finish()
        }
    }

    private fun finishCapture(imagePath: String, isLive: Boolean, isSameSubject: Boolean) {
        logController.d("CameraActivity") { "finishCapture: Creating final result" }
        val finalResult = AVMatchResult(
            processed = true,
            referenceIsValid = true,
            capturedIsLive = isLive,
            isSameSubject = isSameSubject,
            capturedPath = imagePath
        )

        avCameraCallbackHolder.triggerCallback(finalResult)
        cleanupCapturedFrames()
        finish()
    }

    override fun onDestroy() {
        super.onDestroy()
        cleanupCapturedFrames()
    }

    private fun cleanupCapturedFrames() {
        try {
            cacheDir.listFiles()?.filter { it.name.startsWith("captured_frame_") }
                ?.forEach { it.delete() }
        } catch (e: Exception) {
            logController.e("CameraActivity", e) { "Failed to clean up captured frames" }
        }
    }
}

/**
 * Helper object for creating error results
 */
object MatchResult {
    fun error(): AVMatchResult {
        return AVMatchResult(
            processed = false,
            referenceIsValid = false,
            capturedIsLive = false,
            isSameSubject = false,
            capturedPath = null
        )
    }
}
