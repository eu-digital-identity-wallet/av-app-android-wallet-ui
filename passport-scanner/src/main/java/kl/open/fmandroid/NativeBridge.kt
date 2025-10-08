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

/**
 * Safe NativeBridge wrapper with null checks to prevent JNI crashes
 */
object NativeBridge {
    private const val TAG = "NativeBridge"

    // Original native methods - these must match the compiled JNI signatures
    external fun jni_init(configJson: String, modelBasePath: String): Boolean
    external fun jni_process(imagePath: String, isReference: Boolean): ProcessResult
    external fun jni_setDebugSavePath(debugPath: String)
    external fun jni_match(embedding1: FloatArray, embedding2: FloatArray): Boolean
    external fun jni_release()
    external fun jni_getVersion(): String

    // Safe wrapper methods that handle nulls before calling native methods
    fun safeInit(configJson: String?, modelBasePath: String?): Boolean {
        android.util.Log.d(TAG, "safeInit called with configJson: ${configJson != null}, modelBasePath: ${modelBasePath != null}")

        if (configJson.isNullOrEmpty() || modelBasePath.isNullOrEmpty()) {
            android.util.Log.e(TAG, "safeInit: Null or empty parameters, returning false")
            return false
        }

        return try {
            jni_init(configJson, modelBasePath)
        } catch (e: Exception) {
            android.util.Log.e(TAG, "safeInit: Exception in native call", e)
            false
        }
    }

    fun safeProcess(imagePath: String?, isReference: Boolean): ProcessResult {
        android.util.Log.d(TAG, "safeProcess called with imagePath: '$imagePath', isReference: $isReference")

        if (imagePath.isNullOrEmpty()) {
            android.util.Log.e(TAG, "safeProcess: NULL or empty image path, returning empty result")
            return ProcessResult(
                livenessChecked = false,
                isLive = false,
                faceDetected = false,
                embeddingExtracted = false,
                embedding = FloatArray(0)
            )
        }

        return try {
            jni_process(imagePath, isReference)
        } catch (e: Exception) {
            android.util.Log.e(TAG, "safeProcess: Exception in native call", e)
            ProcessResult(
                livenessChecked = false,
                isLive = false,
                faceDetected = false,
                embeddingExtracted = false,
                embedding = FloatArray(0)
            )
        }
    }

    fun safeMatch(embedding1: FloatArray?, embedding2: FloatArray?): Boolean {
        android.util.Log.d(TAG, "safeMatch called with embedding1: ${embedding1?.size ?: 0}, embedding2: ${embedding2?.size ?: 0}")

        if (embedding1 == null || embedding2 == null) {
            android.util.Log.e(TAG, "safeMatch: NULL embeddings, returning false")
            return false
        }

        return try {
            jni_match(embedding1, embedding2)
        } catch (e: Exception) {
            android.util.Log.e(TAG, "safeMatch: Exception in native call", e)
            false
        }
    }
}
