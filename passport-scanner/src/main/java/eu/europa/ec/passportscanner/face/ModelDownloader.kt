/*
 * Copyright (c) 2025 European Commission
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

package eu.europa.ec.passportscanner.face

import android.content.Context
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.businesslogic.extension.isNoConnectionError
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * Handles downloading and preparing model files for face matching SDK
 * Supports both local assets and remote HTTP(S) URLs
 */
class ModelDownloader(
    private val context: Context,
    private val logController: LogController,
) {

    companion object {
        private const val TAG = "ModelDownloader"
    }

    /**
     * Download file from HTTP URL to internal storage
     * @param urlString URL to download from
     * @param destDir Destination directory path
     * @param outputFilename Optional custom filename for the downloaded file. If null, extracts from URL
     * @param expectedSha256 Optional expected SHA-256 hash (hex) for integrity verification
     * @param onProgress Optional callback for download progress (percentage: 0-100)
     * @return The local filename of the downloaded file, or null if failed
     */
    suspend fun downloadModelFromUrl(
        urlString: String,
        destDir: String,
        outputFilename: String? = null,
        expectedSha256: String? = null,
        onProgress: ((Int) -> Unit)? = null,
    ): String? = withContext(Dispatchers.IO) {
        logController.d(TAG) { "downloadModelFromUrl: Starting download from $urlString" }

        val url = URL(urlString)
        val filename = outputFilename ?: url.path.substringAfterLast('/').ifEmpty { "model.onnx" }
        val destFile = File(destDir, filename)

        if (destFile.exists()) {
            logController.d(TAG) { "File already exists. Not downloading." }
            return@withContext filename
        }

        logController.d(TAG) { "downloadModelFromUrl: Downloading to ${destFile.absolutePath}" }

        val tempFile = File(destDir, "$filename.tmp")

        try {
            // Use HttpURLConnection with proper configuration
            val connection = url.openConnection() as HttpURLConnection
            connection.requestMethod = "GET"
            connection.connectTimeout = 30000 // 30 seconds
            connection.readTimeout = 60000 // 60 seconds
            connection.instanceFollowRedirects = true
            connection.setRequestProperty("User-Agent", "Mozilla/5.0")

            connection.connect()

            val responseCode = connection.responseCode
            logController.d(TAG) { "downloadModelFromUrl: Response code: $responseCode" }

            if (responseCode == HttpURLConnection.HTTP_OK) {
                val contentLength = connection.contentLength
                logController.d(TAG) { "downloadModelFromUrl: Content length: $contentLength bytes" }

                connection.inputStream.use { input ->
                    tempFile.outputStream().use { output ->
                        val buffer = ByteArray(8192)
                        var bytesRead: Int
                        var totalBytesRead = 0L
                        var lastLoggedMB = 0L
                        var lastReportedPercentage = 0

                        while (input.read(buffer).also { bytesRead = it } != -1) {
                            coroutineContext.ensureActive()
                            output.write(buffer, 0, bytesRead)
                            totalBytesRead += bytesRead

                            val currentMB = totalBytesRead / (1024 * 1024)
                            val percentage = if (contentLength > 0) {
                                ((totalBytesRead * 100) / contentLength).toInt()
                            } else {
                                0
                            }

                            // Log progress every 10MB
                            if (currentMB >= lastLoggedMB + 10) {
                                logController.d(TAG) { "downloadModelFromUrl: Downloaded $currentMB MB" }
                                lastLoggedMB = currentMB
                            }

                            // Report progress every 5%
                            if (percentage >= lastReportedPercentage + 5) {
                                onProgress?.invoke(percentage)
                                lastReportedPercentage = percentage
                            }
                        }

                        logController.d(TAG) { "downloadModelFromUrl: Download complete: ${totalBytesRead / (1024 * 1024)} MB total" }
                        onProgress?.invoke(100)
                    }
                }

                tempFile.renameTo(destFile)
                logController.d(TAG) { "downloadModelFromUrl: Download complete: ${destFile.length()} bytes" }

                if (expectedSha256 != null) {
                    val actualHash = computeSha256(destFile)
                    if (!actualHash.equals(expectedSha256, ignoreCase = true)) {
                        logController.e(TAG) {
                            "downloadModelFromUrl: SHA-256 integrity check FAILED. " +
                                    "Expected: $expectedSha256, Got: $actualHash"
                        }
                        destFile.delete()
                        return@withContext null
                    }
                    logController.d(TAG) { "downloadModelFromUrl: SHA-256 integrity check passed" }
                }

                filename
            } else {
                logController.e(TAG) { "downloadModelFromUrl: HTTP error code: $responseCode" }
                null
            }
        } catch (e: Exception) {
            logController.e(TAG, e) { "downloadModelFromUrl: Failed to download from $urlString" }
            if (e.isNoConnectionError()) throw e
            null
        } finally {
            // Clean up temp file if it wasn't successfully renamed
            tempFile.delete()
        }
    }

    private fun computeSha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(8192)
            var bytesRead: Int
            while (input.read(buffer).also { bytesRead = it } != -1) {
                digest.update(buffer, 0, bytesRead)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    /**
     * Copy asset file to internal storage if it doesn't exist
     * @param assetName Name of the asset file
     * @param destDir Destination directory path
     */
    private fun copyAssetIfNeeded(assetName: String, destDir: String) {
        if (assetName.isEmpty()) return

        val destFile = File(destDir, assetName)
        if (!destFile.exists()) {
            try {
                context.assets.open(assetName).use { input ->
                    destFile.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }
                logController.d(TAG) { "copyAssetIfNeeded: Copied asset $assetName to ${destFile.absolutePath}" }
            } catch (e: Exception) {
                logController.e(TAG, e) { "Failed to copy asset: $assetName" }
            }
        }
    }

    /**
     * Prepare model file (either from asset or URL) to internal storage
     * @param modelPath Either an asset filename or HTTP(S) URL
     * @param destDir Destination directory path
     * @param outputFilename Optional custom filename for downloaded files. Only used for URLs
     * @param expectedSha256 Optional expected SHA-256 hash (hex) for integrity verification
     * @param onProgress Optional callback for download progress (percentage: 0-100)
     * @return The local filename, or null if preparation failed
     */
    suspend fun prepareModel(
        modelPath: String,
        destDir: String,
        outputFilename: String? = null,
        expectedSha256: String? = null,
        onProgress: ((Int) -> Unit)? = null,
    ): String? {
        if (modelPath.isEmpty()) return null

        return if (modelPath.startsWith("https://")) {
            downloadModelFromUrl(modelPath, destDir, outputFilename, expectedSha256, onProgress)
        } else if (modelPath.startsWith("http://")) {
            logController.e(TAG) { "Rejecting insecure HTTP URL for model download: $modelPath" }
            null
        } else {
            // Copy from assets
            copyAssetIfNeeded(modelPath, destDir)
            modelPath
        }
    }
}
