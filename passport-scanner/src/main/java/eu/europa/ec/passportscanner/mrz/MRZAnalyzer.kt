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
package eu.europa.ec.passportscanner.mrz

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Rect
import android.view.View
import android.widget.ImageView
import android.widget.RelativeLayout
import androidx.camera.core.ImageProxy
import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.text.TextRecognition
import com.google.mlkit.vision.text.latin.TextRecognizerOptions
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.passportscanner.R
import eu.europa.ec.passportscanner.SmartScannerActivity
import eu.europa.ec.passportscanner.scanner.BaseImageAnalyzer
import eu.europa.ec.passportscanner.utils.BitmapUtils
import eu.europa.ec.passportscanner.utils.draw.BoundingBoxDraw
import eu.europa.ec.passportscanner.utils.extension.setBrightness
import eu.europa.ec.passportscanner.utils.extension.setContrast
import eu.europa.ec.passportscanner.utils.extension.toPx

abstract class MRZAnalyzer(
    override val activity: Activity,
    override val intent: Intent,

    override val logController: LogController,
) : BaseImageAnalyzer() {

    companion object {
        // Intentional: shows detected text regions to guide users in positioning the passport correctly
        private const val SHOW_DEBUG_BOUNDING_BOXES = true
        val GUIDE_HEIGHT_IN_PX = 75.toPx
    }

    private fun initializeBoundingBoxes(): RelativeLayout? {
        if (!SHOW_DEBUG_BOUNDING_BOXES) return null

        val bdParent = activity.findViewById<RelativeLayout>(R.id.rect_bounding_layout)

        if (bdParent != null && bdParent.childCount > 1) {
            bdParent.removeAllViews()
        }

        return bdParent
    }

    private fun calculateAdjustedBoundingBox(
        boundingBox: Rect,
        rotatedBF: Bitmap,
        viewFinder: View,
        rectGuide: ImageView
    ): Rect {
        // Scale factors between the cropped MRZ image and preview view
        val imageToViewRatio = rotatedBF.width.toFloat() / viewFinder.width.toFloat()
        val scaleX = 1.0f / imageToViewRatio
        val scaleY = 1.0f / imageToViewRatio

        // Scale the bounding box coordinates from cropped image to preview coordinates
        val scaledRect = Rect(
            (boundingBox.left * scaleX).toInt(),
            (boundingBox.top * scaleY).toInt(),
            (boundingBox.right * scaleX).toInt(),
            (boundingBox.bottom * scaleY).toInt()
        )

        // Calculate offsets for where the MRZ crop area starts in the preview
        val mrzCropX = 9.toPx
        val mrzCropY = viewFinder.height - rectGuide.height - GUIDE_HEIGHT_IN_PX / 4

        // Apply offsets to position the boxes correctly in the preview
        scaledRect.offset(mrzCropX, mrzCropY)

        return scaledRect
    }

    private fun addBoundingBoxToView(
        boundingBox: Rect,
        bdParent: RelativeLayout?,
        rotatedBF: Bitmap,
        viewFinder: View,
        rectGuide: ImageView
    ) {
        if (!SHOW_DEBUG_BOUNDING_BOXES || bdParent == null) return

        val adjustedRect =
            calculateAdjustedBoundingBox(boundingBox, rotatedBF, viewFinder, rectGuide)
        val element = BoundingBoxDraw(activity, adjustedRect)
        bdParent.addView(element)
    }

    @SuppressLint("UnsafeExperimentalUsageError", "UnsafeOptInUsageError")
    override fun analyze(imageProxy: ImageProxy) {
        val bitmap = BitmapUtils.getBitmap(imageProxy, logController)
        if (bitmap == null) {
            imageProxy.close()
            return
        }
        bitmap.let { bf ->
            val rotation = imageProxy.imageInfo.rotationDegrees
            bf.apply {
                // Increase brightness and contrast for clearer image to be processed
                setContrast(1.1F)
                setBrightness(3F)
            }

            val rectGuide = activity.findViewById<ImageView>(R.id.scanner_overlay)
            val viewFinder = activity.findViewById<View>(R.id.view_finder)

            if (rectGuide == null || viewFinder == null || viewFinder.width == 0 || viewFinder.height == 0) {
                imageProxy.close()
                return
            }

            var rotatedBF = BitmapUtils.rotateImage(bf, rotation)

            // Crop preview area to match viewfinder aspect ratio
            val imageToViewRatio = rotatedBF.width.toFloat() / viewFinder.width.toFloat()
            val cropHeight = viewFinder.height * imageToViewRatio
            val cropTop = ((rotatedBF.height - cropHeight) / 2).coerceAtLeast(0f).toInt()
            val finalCropHeight = cropHeight.toInt().coerceAtMost(rotatedBF.height - cropTop)

            if (finalCropHeight <= 0) {
                imageProxy.close()
                return
            }

            rotatedBF = Bitmap.createBitmap(
                rotatedBF,
                0,
                cropTop,
                rotatedBF.width,
                finalCropHeight
            )

            // Crop MRZ area
            val mrzCropX = (25 - 16).toPx * imageToViewRatio
            val mrzCropY = (viewFinder.height - 30.toPx - rectGuide.height) * imageToViewRatio
            val mrzCropWidth = rectGuide.width * imageToViewRatio
            val mrzCropHeight = rectGuide.height * imageToViewRatio

            // Ensure safe cropping for MRZ area within the already cropped rotatedBF
            val safeMrzX = mrzCropX.toInt().coerceIn(0, (rotatedBF.width - 1).coerceAtLeast(0))
            val safeMrzY = mrzCropY.toInt().coerceIn(0, (rotatedBF.height - 1).coerceAtLeast(0))
            val safeMrzWidth = mrzCropWidth.toInt().coerceIn(1, (rotatedBF.width - safeMrzX).coerceAtLeast(1))
            val safeMrzHeight = mrzCropHeight.toInt().coerceIn(1, (rotatedBF.height - safeMrzY).coerceAtLeast(1))

            val inputBitmap = Bitmap.createBitmap(
                rotatedBF,
                safeMrzX,
                safeMrzY,
                safeMrzWidth,
                safeMrzHeight
            )
            val inputRot = 0

            // Pass image to an ML Kit Vision API
            logController.d("${SmartScannerActivity.TAG}/SmartScanner") { "MRZ MLKit: start" }
            val image = InputImage.fromBitmap(inputBitmap, inputRot)
            val recognizer = TextRecognition.getClient(TextRecognizerOptions.DEFAULT_OPTIONS)

            recognizer.process(image)
                .addOnSuccessListener { visionText ->
                    val blocks = visionText.textBlocks

                    val bdParent = initializeBoundingBoxes()

                    // Collect text blocks with bounding boxes for reconstruction
                    val textBlocks = mutableListOf<MRZLineReconstructor.TextBlock>()
                    for (i in blocks.indices) {
                        val lines = blocks[i].lines
                        for (j in lines.indices) {
                            lines[j].boundingBox?.let { boundingBox ->
                                // Clean the block text before reconstruction
                                val cleanedText = MRZCleaner.cleanBlockText(lines[j].text)

                                if (cleanedText.isNotEmpty()) {
                                    textBlocks.add(
                                        MRZLineReconstructor.TextBlock(
                                            text = cleanedText,
                                            boundingBox = boundingBox
                                        )
                                    )
                                }

                                // Add bounding box to debug view
                                addBoundingBoxToView(
                                    boundingBox,
                                    bdParent,
                                    rotatedBF,
                                    viewFinder,
                                    rectGuide
                                )
                            }
                        }
                    }

                    val rawFullRead = MRZLineReconstructor.reconstruct(textBlocks)

                    try {
                        val cleanMRZ = MRZCleaner.clean(rawFullRead, logController, skipReconstruction = true)
                        processResult(result = cleanMRZ, bitmap = bf, rotation = rotation)
                    } catch (_: Exception) {
                        logController.d("${SmartScannerActivity.TAG}/SmartScanner") { "MRZ parsing failed" }
                    }
                    imageProxy.close()
                }
                .addOnFailureListener { _ ->
                    logController.d("${SmartScannerActivity.TAG}/SmartScanner") { "Camera analysis failed" }
                    imageProxy.close()
                }
        }
    }

    abstract fun processResult(result: String, bitmap: Bitmap, rotation: Int)
}
