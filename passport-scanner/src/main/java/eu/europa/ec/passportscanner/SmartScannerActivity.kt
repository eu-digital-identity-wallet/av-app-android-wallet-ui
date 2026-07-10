/*
 * Copyright (C) 2020 Newlogic Pte. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 *
 */
package eu.europa.ec.passportscanner

import android.Manifest
import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.ActivityInfo
import android.content.pm.PackageManager
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.util.Size
import android.view.MotionEvent
import android.view.OrientationEventListener
import android.view.Surface
import android.view.View
import android.view.View.GONE
import android.view.View.OnClickListener
import android.view.View.VISIBLE
import android.view.ViewTreeObserver
import android.view.Window
import android.widget.TextView
import androidx.camera.camera2.interop.Camera2Interop
import androidx.camera.core.Camera
import androidx.camera.core.CameraInfoUnavailableException
import androidx.camera.core.CameraSelector
import androidx.camera.core.FocusMeteringAction
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageCapture
import androidx.camera.core.MeteringPointFactory
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.core.SurfaceOrientedMeteringPointFactory
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.constraintlayout.widget.Guideline
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.content.IntentCompat
import com.google.android.material.snackbar.Snackbar
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.passportscanner.mrz.MRZAnalyzer.Companion.GUIDE_HEIGHT_IN_PX
import eu.europa.ec.passportscanner.nfc.NFCScanAnalyzer
import eu.europa.ec.passportscanner.scanner.BaseActivity
import eu.europa.ec.passportscanner.scanner.SmartScannerException
import eu.europa.ec.passportscanner.scanner.config.Config
import eu.europa.ec.passportscanner.scanner.config.Orientation
import eu.europa.ec.passportscanner.scanner.config.ScannerOptions
import eu.europa.ec.passportscanner.utils.CameraUtils.isLedFlashAvailable
import eu.europa.ec.passportscanner.utils.extension.toPx
import eu.europa.ec.resourceslogic.R.string
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import org.koin.android.ext.android.inject

class SmartScannerActivity : BaseActivity(), OnClickListener {

    companion object {
        val TAG: String = SmartScannerActivity::class.java.simpleName
        const val SCANNER_OPTIONS = "scanner_options"
        const val SCANNER_RESULT = "scanner_result"
    }

    private val logController: LogController by inject()

    private val REQUEST_CODE_PERMISSIONS = 10
    private val REQUEST_CODE_PERMISSIONS_VERSION_R = 2296
    private val REQUIRED_PERMISSIONS = arrayOf(
        Manifest.permission.CAMERA
    )
    private var config: Config? = null
    private var preview: Preview? = null
    private var imageAnalyzer: ImageAnalysis? = null
    private var imageCapture: ImageCapture? = null
    private var camera: Camera? = null
    private var scannerOptions: ScannerOptions? = null
    private var cameraProvider: ProcessCameraProvider? = null
    private var orientation: String? = null

    private var flashButton: View? = null
    private var closeButton: View? = null
    private var rectangle: View? = null
    private var rectangleGuide: View? = null
    private var guideContainer: View? = null
    private var guideWidth: View? = null
    private var xGuideView: View? = null
    private var yGuideView: View? = null
    private var captureHeaderText: TextView? = null
    private var captureSubHeaderText: TextView? = null

    private lateinit var modelLayoutView: View
    private lateinit var coordinatorLayoutView: View
    private lateinit var viewFinder: PreviewView
    private lateinit var cameraExecutor: ExecutorService

    private val orientationEventListener by lazy {
        object : OrientationEventListener(this) {
            override fun onOrientationChanged(orientation: Int) {
                if (orientation == ORIENTATION_UNKNOWN) {
                    return
                }

                val rotation = when (orientation) {
                    in 45 until 135 -> Surface.ROTATION_270
                    in 135 until 225 -> Surface.ROTATION_180
                    in 225 until 315 -> Surface.ROTATION_90
                    else -> Surface.ROTATION_0
                }

                imageAnalyzer?.targetRotation = rotation
                imageCapture?.targetRotation = rotation
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        supportRequestWindowFeature(Window.FEATURE_NO_TITLE)
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_smart_scanner)

        // assign view ids
        coordinatorLayoutView = findViewById(R.id.coordinator_layout)
        modelLayoutView = findViewById(R.id.view_layout)
        viewFinder = findViewById(R.id.view_finder)
        flashButton = findViewById(R.id.flash_button)
        closeButton = findViewById(R.id.close_button)
        rectangle = findViewById(R.id.rect_image)
        rectangleGuide = findViewById(R.id.scanner_overlay)
        guideContainer = findViewById(R.id.guide_layout)
        guideWidth = findViewById(R.id.guide_width)
        xGuideView = findViewById(R.id.x_guide)
        yGuideView = findViewById(R.id.y_guide)
        captureHeaderText = findViewById(R.id.capture_header_text)
        captureSubHeaderText = findViewById(R.id.capture_sub_header_text)

        // Scanner setup from intent
        hideActionBar()
        // Use scanner options directly if no scanner type is called
        val options: ScannerOptions? =
            IntentCompat.getParcelableExtra(intent, SCANNER_OPTIONS, ScannerOptions::class.java)
        options?.let {
            logController.d(TAG) { "scannerOptions: $it" }
            scannerOptions = options
        } ?: run {
            throw SmartScannerException("Please set proper scanner options to be able to use ID PASS Smart Scanner.")
        }
        config = scannerOptions?.config ?: Config.default
        // Set orientation to PORTRAIT as default
        orientation = config?.orientation ?: Orientation.PORTRAIT.value
        // Request camera permissions
        if (allPermissionsGranted()) {
            setupConfiguration()
        } else {
            requestPermissions()
        }
        cameraExecutor = Executors.newSingleThreadExecutor()
    }

    private fun setupConfiguration() {
        runOnUiThread {
            showMRZGuide()

            val analyzer = NFCScanAnalyzer(this, intent, logController)
            viewFinder.visibility = VISIBLE
            // Set Analyzer and start camera
            startCamera(analyzer)
        }
        setupViews()
    }

    override fun onStart() {
        super.onStart()
        orientationEventListener.enable()
    }

    override fun onStop() {
        super.onStop()
        orientationEventListener.disable()
    }

    override fun onDestroy() {
        super.onDestroy()
        cameraExecutor.shutdown()
    }

    @SuppressLint("ClickableViewAccessibility", "UnsafeOptInUsageError")
    private fun startCamera(analyzer: ImageAnalysis.Analyzer? = null) {
        viewFinder.post {
            if (viewFinder.display == null) return@post
            this.getSystemService(CAMERA_SERVICE) as CameraManager
            val cameraProviderFuture = ProcessCameraProvider.getInstance(this)
            cameraProviderFuture.addListener({
                val resolution = Size(640, 480)
                val rotation = viewFinder.display.rotation
                // Used to bind the lifecycle of cameras to the lifecycle owner
                cameraProvider = cameraProviderFuture.get()
                // Preview
                val resolutionSelector640x480 = ResolutionSelector.Builder()
                    .setResolutionStrategy(
                        ResolutionStrategy(
                            resolution,
                            ResolutionStrategy.FALLBACK_RULE_CLOSEST_LOWER_THEN_HIGHER
                        )
                    )
                    .build()
                preview = Preview.Builder()
                    .setResolutionSelector(resolutionSelector640x480)
                    .setTargetRotation(rotation)
                    .build()
                val imageAnalysisBuilder = ImageAnalysis.Builder()
                    .setResolutionSelector(resolutionSelector640x480)
                    .setTargetRotation(rotation)
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)

                val camera2InterOp = Camera2Interop.Extender(imageAnalysisBuilder)
                camera2InterOp.setCaptureRequestOption(
                    CaptureRequest.CONTROL_AF_MODE,
                    CaptureRequest.CONTROL_AF_MODE_AUTO
                )
                camera2InterOp.setCaptureRequestOption(
                    CaptureRequest.CONTROL_AE_MODE,
                    CaptureRequest.CONTROL_AE_MODE_ON
                )

                imageAnalyzer = imageAnalysisBuilder
                    .build()
                    .also {
                        analyzer?.let { analysis -> it.setAnalyzer(cameraExecutor, analysis) }
                    }

                // Create configuration object for the image capture use case
                val resolutionSelector1080x1920 = ResolutionSelector.Builder()
                    .setResolutionStrategy(
                        ResolutionStrategy(
                            Size(1080, 1920),
                            ResolutionStrategy.FALLBACK_RULE_CLOSEST_LOWER_THEN_HIGHER
                        )
                    )
                    .build()
                imageCapture = ImageCapture.Builder()
                    .setResolutionSelector(resolutionSelector1080x1920)
                    .setTargetRotation(Surface.ROTATION_0)
                    .setCaptureMode(ImageCapture.CAPTURE_MODE_MAXIMIZE_QUALITY)
                    .build()
                // Select back camera
                val cameraSelector =
                    CameraSelector.Builder().requireLensFacing(CameraSelector.LENS_FACING_BACK)
                        .build()
                try {
                    // Unbind use cases before rebinding
                    cameraProvider?.unbindAll()
                    // Bind use cases to camera
                    camera = if (analyzer != null) {
                        cameraProvider?.bindToLifecycle(
                            this,
                            cameraSelector,
                            preview,
                            imageAnalyzer,
                            imageCapture
                        )
                    } else {
                        cameraProvider?.bindToLifecycle(
                            this,
                            cameraSelector,
                            preview,
                            imageCapture
                        )
                    }
                    preview?.surfaceProvider = viewFinder.surfaceProvider
                    logController.d(TAG) {
                        "Measured size: ${viewFinder.width}x${viewFinder.height}"
                    }
                    // Tap to focus
                    viewFinder.afterMeasured {
                        viewFinder.setOnTouchListener { _, event ->
                            return@setOnTouchListener when (event.action) {
                                MotionEvent.ACTION_DOWN -> {
                                    true
                                }

                                MotionEvent.ACTION_UP -> {
                                    val factory: MeteringPointFactory =
                                        SurfaceOrientedMeteringPointFactory(
                                            viewFinder.width.toFloat(), viewFinder.height.toFloat()
                                        )
                                    val autoFocusPoint = factory.createPoint(event.x, event.y)
                                    try {
                                        camera?.cameraControl?.startFocusAndMetering(
                                            FocusMeteringAction.Builder(
                                                autoFocusPoint,
                                                FocusMeteringAction.FLAG_AF
                                            ).apply {
                                                //focus only when the user tap the preview
                                                disableAutoCancel()
                                            }.build()
                                        )
                                    } catch (e: CameraInfoUnavailableException) {
                                        logController.e(TAG, e) {
                                            "cannot access camera"
                                        }
                                    }
                                    true
                                }

                                else -> false // Unhandled event.
                            }
                        }
                    }
                } catch (exc: Exception) {
                    logController.e(TAG, exc) { "Use case binding failed" }
                }
            }, ContextCompat.getMainExecutor(this))
        }
    }

    private fun setupViews() {
        // scanner layout size
        val topGuideline = findViewById<Guideline>(R.id.top)
        val bottomGuideline = findViewById<Guideline>(R.id.bottom)
        // scanner sizes available for Portrait only
        if (orientation == Orientation.PORTRAIT.value) {
            bottomGuideline.setGuidelinePercent(0.625F)
            topGuideline.setGuidelinePercent(0.275F)
        }
        // flash
        flashButton?.visibility = if (isLedFlashAvailable(this)) VISIBLE else GONE
        // capture text header
        captureHeaderText?.text = config?.header ?: ""
        // capture text sub-header
        captureSubHeaderText?.text = config?.subHeader ?: ""
        // Device orientation
        if (orientation == Orientation.LANDSCAPE.value) {
            this.requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_REVERSE_LANDSCAPE
        }
        // assign camera click listeners
        closeButton?.setOnClickListener(this)
        flashButton?.setOnClickListener(this)
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<String>,
        grantResults: IntArray,
    ) {
        when (requestCode) {
            REQUEST_CODE_PERMISSIONS_VERSION_R,
            REQUEST_CODE_PERMISSIONS,
                -> {
                if (allPermissionsGranted()) {
                    setupConfiguration()
                } else {
                    val snackBar: Snackbar = Snackbar.make(
                        coordinatorLayoutView,
                        string.required_perms_not_given,
                        Snackbar.LENGTH_INDEFINITE
                    )
                    snackBar.setAction(string.settings) {
                        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                        val uri = Uri.fromParts("package", packageName, null)
                        intent.data = uri
                        startActivity(intent)
                    }
                    snackBar.show()
                }
            }
        }
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
    }

    private fun requestPermissions() =
        ActivityCompat.requestPermissions(this, REQUIRED_PERMISSIONS, REQUEST_CODE_PERMISSIONS)

    private fun allPermissionsGranted() = REQUIRED_PERMISSIONS.all {
        ContextCompat.checkSelfPermission(baseContext, it) == PackageManager.PERMISSION_GRANTED
    }

    override fun onClick(view: View) {
        when (view.id) {
            R.id.close_button -> onBackPressedDispatcher.onBackPressed()
            R.id.flash_button -> {
                flashButton?.let {
                    if (it.isSelected) {
                        it.isSelected = false
                        enableFlashlight(false)
                    } else {
                        it.isSelected = true
                        enableFlashlight(true)
                    }
                }
            }
        }
    }

    private fun enableFlashlight(torch: Boolean) {
        camera?.cameraControl?.enableTorch(torch)
    }

    private inline fun View.afterMeasured(crossinline block: () -> Unit) {
        if (measuredWidth > 0 && measuredHeight > 0) {
            block()
        } else {
            viewTreeObserver.addOnGlobalLayoutListener(object :
                ViewTreeObserver.OnGlobalLayoutListener {
                override fun onGlobalLayout() {
                    if (measuredWidth > 0 && measuredHeight > 0) {
                        viewTreeObserver.removeOnGlobalLayoutListener(this)
                        block()
                    }
                }
            })
        }
    }

    private fun showMRZGuide() {
        guideContainer?.alpha = 1f

        config?.let { _ ->
            viewFinder.post {
                val width = viewFinder.width - 21.toPx

                rectangleGuide?.layoutParams?.width = width
                guideWidth?.layoutParams?.width = width

                //set height
                val nHeight = GUIDE_HEIGHT_IN_PX
                rectangleGuide?.layoutParams?.height = nHeight

                //set default position

                val xPercentage = (viewFinder.width - width).div(2)
                val yPercentage = viewFinder.height - nHeight - 30.toPx

                xGuideView?.layoutParams?.width = xPercentage
                yGuideView?.layoutParams?.height = yPercentage

                xGuideView?.requestLayout()
                yGuideView?.requestLayout()
            }
            rectangleGuide?.requestLayout()
        }
    }
}
