/*
 * Copyright 2020 Google LLC. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.passportscanner.utils

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.ImageFormat
import android.graphics.Matrix
import android.graphics.Rect
import android.graphics.YuvImage
import android.media.Image.Plane
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageProxy
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.passportscanner.utils.transform.FrameMetadata
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

/**
 * Utils functions for bitmap conversions.
 */
object BitmapUtils {
    /**
     * Converts NV21 format byte buffer to bitmap.
     */
    fun getBitmap(
        logController: LogController,
        data: ByteBuffer,
        metadata: FrameMetadata
    ): Bitmap? {
        data.rewind()
        val imageInBuffer = ByteArray(data.limit())
        data.get(imageInBuffer, 0, imageInBuffer.size)
        try {
            val image =
                YuvImage(
                    imageInBuffer, ImageFormat.NV21, metadata.width, metadata.height, null
                )
            return ByteArrayOutputStream().use { stream ->
                image.compressToJpeg(Rect(0, 0, metadata.width, metadata.height), 80, stream)
                BitmapFactory.decodeByteArray(stream.toByteArray(), 0, stream.size())
            }
        } catch (e: Exception) {
            logController.e("VisionProcessorBase", e)
        }
        return null
    }

    /**
     * Converts a YUV_420_888 image from CameraX API to a bitmap.
     */
    @ExperimentalGetImage
    fun getBitmap(image: ImageProxy, logController: LogController): Bitmap? {
        val planes = image.image?.planes ?: return null
        val frameMetadata =
            FrameMetadata.Builder()
                .setWidth(image.width)
                .setHeight(image.height)
                .build()

        val nv21Buffer = yuv420ThreePlanesToNV21(
            planes,
            image.width,
            image.height
        )
        return getBitmap(logController, nv21Buffer, frameMetadata)
    }

    /**
     * Converts YUV_420_888 to NV21 bytebuffer.
     *
     *
     * The NV21 format consists of a single byte array containing the Y, U and V values. For an
     * image of size S, the first S positions of the array contain all the Y values. The remaining
     * positions contain interleaved V and U values. U and V are subsampled by a factor of 2 in both
     * dimensions, so there are S/4 U values and S/4 V values. In summary, the NV21 array will contain
     * S Y values followed by S/4 VU values: YYYYYYYYYYYYYY(...)YVUVUVUVU(...)VU
     *
     *
     * YUV_420_888 is a generic format that can describe any YUV image where U and V are subsampled
     * by a factor of 2 in both dimensions. [Image.getPlanes] returns an array with the Y, U and
     * V planes. The Y plane is guaranteed not to be interleaved, so we can just copy its values into
     * the first part of the NV21 array. The U and V planes may already have the representation in the
     * NV21 format. This happens if the planes share the same buffer, the V buffer is one position
     * before the U buffer and the planes have a pixelStride of 2. If this is case, we can just copy
     * them to the NV21 array.
     */
    private fun yuv420ThreePlanesToNV21(
        yuv420888planes: Array<Plane?>, width: Int, height: Int
    ): ByteBuffer {
        val imageSize = width * height
        val out = ByteArray(imageSize + 2 * (imageSize / 4))

        if (areUVPlanesNV21(yuv420888planes, width, height)) {
            // Copy the Y values.
            yuv420888planes[0]!!.buffer.get(out, 0, imageSize)

            val uBuffer = yuv420888planes[1]!!.buffer
            val vBuffer = yuv420888planes[2]!!.buffer
            // Get the first V value from the V buffer, since the U buffer does not contain it.
            vBuffer.get(out, imageSize, 1)
            // Copy the first U value and the remaining VU values from the U buffer.
            uBuffer.get(out, imageSize + 1, 2 * imageSize / 4 - 1)
        } else {
            // Fallback to copying the UV values one by one, which is slower but also works.
            // Unpack Y.
            unpackPlane(yuv420888planes[0]!!, width, height, out, 0, 1)
            // Unpack U.
            unpackPlane(yuv420888planes[1]!!, width, height, out, imageSize + 1, 2)
            // Unpack V.
            unpackPlane(yuv420888planes[2]!!, width, height, out, imageSize, 2)
        }

        return ByteBuffer.wrap(out)
    }

    /**
     * Checks if the UV plane buffers of a YUV_420_888 image are in the NV21 format.
     */
    private fun areUVPlanesNV21(planes: Array<Plane?>, width: Int, height: Int): Boolean {
        val imageSize = width * height

        val uBuffer = planes[1]!!.buffer
        val vBuffer = planes[2]!!.buffer

        // Backup buffer properties.
        val vBufferPosition = vBuffer.position()
        val uBufferLimit = uBuffer.limit()

        // Advance the V buffer by 1 byte, since the U buffer will not contain the first V value.
        vBuffer.position(vBufferPosition + 1)
        // Chop off the last byte of the U buffer, since the V buffer will not contain the last U value.
        uBuffer.limit(uBufferLimit - 1)

        // Check that the buffers are equal and have the expected number of elements.
        val areNV21 =
            (vBuffer.remaining() == (2 * imageSize / 4 - 2)) && (vBuffer.compareTo(uBuffer) == 0)

        // Restore buffers to their initial state.
        vBuffer.position(vBufferPosition)
        uBuffer.limit(uBufferLimit)

        return areNV21
    }

    /**
     * Unpack an image plane into a byte array.
     *
     *
     * The input plane data will be copied in 'out', starting at 'offset' and every pixel will be
     * spaced by 'pixelStride'. Note that there is no row padding on the output.
     */
    private fun unpackPlane(
        plane: Plane, width: Int, height: Int, out: ByteArray, offset: Int, pixelStride: Int
    ) {
        val buffer = plane.buffer
        buffer.rewind()

        // Compute the size of the current plane.
        // We assume that it has the aspect ratio as the original image.
        val numRow = (buffer.limit() + plane.rowStride - 1) / plane.rowStride
        if (numRow == 0) {
            return
        }
        val scaleFactor = height / numRow
        val numCol = width / scaleFactor

        // Extract the data in the output buffer.
        var outputPos = offset
        var rowStart = 0
        (0..<numRow).forEach { _ ->
            var inputPos = rowStart
            (0..<numCol).forEach { _ ->
                out[outputPos] = buffer.get(inputPos)
                outputPos += pixelStride
                inputPos += plane.pixelStride
            }
            rowStart += plane.rowStride
        }
    }


    fun rotateImage(myBitmap: Bitmap, rotation: Int): Bitmap {
        val matrix = Matrix()
        when (rotation) {
            90 -> matrix.postRotate(90f)
            180 -> matrix.postRotate(180f)
            270 -> matrix.postRotate(270f)
        }

        return Bitmap.createBitmap(
            myBitmap,
            0,
            0,
            myBitmap.width,
            myBitmap.height,
            matrix,
            true
        )
    }
}
