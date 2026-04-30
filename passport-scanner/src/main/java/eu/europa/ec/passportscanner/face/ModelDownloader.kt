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
import kotlin.coroutines.coroutineContext
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

    private suspend fun downloadModelFromUrl(
        urlString: String,
        destDir: String,
        outputFilename: String?,
        expectedSha256: String,
        onProgress: ((Int) -> Unit)?,
    ): String? = withContext(Dispatchers.IO) {
        logController.d(TAG) { "downloadModelFromUrl: Starting download from $urlString" }

        val url = URL(urlString)
        val filename = outputFilename ?: url.path.substringAfterLast('/').ifEmpty { "model.onnx" }
        val destFile = File(destDir, filename)

        getCachedModelIfValid(destFile, expectedSha256)?.let { return@withContext it }

        logController.d(TAG) { "downloadModelFromUrl: Downloading to ${destFile.absolutePath}" }

        val tempFile = File(destDir, "$filename.tmp")

        try {
            val connection = url.openConnection() as HttpURLConnection
            connection.requestMethod = "GET"
            connection.connectTimeout = 30000
            connection.readTimeout = 60000
            connection.instanceFollowRedirects = true
            connection.setRequestProperty("User-Agent", "Mozilla/5.0")

            connection.connect()

            val responseCode = connection.responseCode
            logController.d(TAG) { "downloadModelFromUrl: Response code: $responseCode" }

            if (responseCode != HttpURLConnection.HTTP_OK) {
                logController.e(TAG) { "downloadModelFromUrl: HTTP error code: $responseCode" }
                return@withContext null
            }

            streamToFile(connection, tempFile, onProgress)

            if (!verifyAndFinalize(tempFile, destFile, expectedSha256)) {
                return@withContext null
            }

            filename
        } catch (e: Exception) {
            logController.e(TAG, e) { "downloadModelFromUrl: Failed to download from $urlString" }
            if (e.isNoConnectionError()) throw e
            null
        } finally {
            if (tempFile.exists() && !tempFile.delete()) {
                logController.e(TAG) { "Failed to delete temp file: ${tempFile.absolutePath}" }
            }
        }
    }

    private fun getCachedModelIfValid(destFile: File, expectedSha256: String): String? {
        if (!destFile.exists()) return null

        val actual = sha256Hex(destFile)
        if (actual.lowercase() == expectedSha256.lowercase()) {
            logController.d(TAG) { "Cached model hash verified." }
            return destFile.name
        }

        logController.e(TAG) { "Cached model hash mismatch — expected $expectedSha256, got $actual. Re-downloading." }
        if (!destFile.delete()) {
            logController.e(TAG) { "Failed to delete stale cached model: ${destFile.absolutePath}" }
        }
        return null
    }

    private suspend fun streamToFile(
        connection: HttpURLConnection,
        tempFile: File,
        onProgress: ((Int) -> Unit)?,
    ) {
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
                    val percentage = calculatePercentage(totalBytesRead, contentLength)

                    if (currentMB >= lastLoggedMB + 10) {
                        logController.d(TAG) { "downloadModelFromUrl: Downloaded $currentMB MB" }
                        lastLoggedMB = currentMB
                    }

                    if (percentage >= lastReportedPercentage + 5) {
                        onProgress?.invoke(percentage)
                        lastReportedPercentage = percentage
                    }
                }

                logController.d(TAG) { "downloadModelFromUrl: Download complete: ${totalBytesRead / (1024 * 1024)} MB total" }
                onProgress?.invoke(100)
            }
        }
    }

    private fun calculatePercentage(totalBytesRead: Long, contentLength: Int): Int {
        if (contentLength <= 0) return 0
        return ((totalBytesRead * 100) / contentLength).toInt()
    }

    private fun verifyAndFinalize(tempFile: File, destFile: File, expectedSha256: String): Boolean {
        val actual = sha256Hex(tempFile)
        if (actual.lowercase() != expectedSha256.lowercase()) {
            if (!tempFile.delete()) {
                logController.e(TAG) { "Failed to delete temp file after hash mismatch: ${tempFile.absolutePath}" }
            }
            logController.e(TAG) { "Model hash mismatch — expected $expectedSha256, got $actual. Aborting." }
            return false
        }
        logController.d(TAG) { "Model hash verified." }
        if (!tempFile.renameTo(destFile)) {
            logController.e(TAG) { "Failed to rename temp file to ${destFile.absolutePath}" }
            return false
        }
        logController.d(TAG) { "downloadModelFromUrl: Download complete: ${destFile.length()} bytes" }
        return true
    }

    private fun sha256Hex(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(8192)
            var read: Int
            while (input.read(buffer).also { read = it } != -1) {
                digest.update(buffer, 0, read)
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
     * Prepare a model from either an APK asset or a remote URL with a pinned SHA-256.
     *
     * @param source Where to fetch the model from. Remote sources carry their own hash,
     *               so adding a URL without a hash is impossible at the type level.
     * @param destDir Destination directory path
     * @param outputFilename Optional custom filename for downloaded files. Only used for Remote sources
     * @param onProgress Optional callback for download progress (percentage: 0-100)
     * @return The local filename, or null if preparation failed
     */
    suspend fun prepareModel(
        source: FaceMatchModelSource,
        destDir: String,
        outputFilename: String? = null,
        onProgress: ((Int) -> Unit)? = null,
    ): String? {
        return when (source) {
            is FaceMatchModelSource.Asset -> {
                if (source.filename.isEmpty()) return null
                copyAssetIfNeeded(source.filename, destDir)
                source.filename
            }

            is FaceMatchModelSource.Remote -> {
                if (!source.url.startsWith("https://")) {
                    logController.e(TAG) { "Rejecting non-https URL for model download: ${source.url}" }
                    return null
                }
                downloadModelFromUrl(
                    urlString = source.url,
                    destDir = destDir,
                    outputFilename = outputFilename,
                    expectedSha256 = source.sha256Hex,
                    onProgress = onProgress,
                )
            }
        }
    }
}
