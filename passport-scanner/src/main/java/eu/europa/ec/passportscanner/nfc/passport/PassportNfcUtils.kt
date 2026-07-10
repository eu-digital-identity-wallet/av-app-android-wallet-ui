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
package eu.europa.ec.passportscanner.nfc.passport

import android.graphics.Bitmap
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.passportscanner.utils.ImageUtils
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.IOException
import java.io.InputStream
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Security
import java.security.cert.CertPathBuilder
import java.security.cert.CertPathBuilderException
import java.security.cert.CertStore
import java.security.cert.Certificate
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.PKIXBuilderParameters
import java.security.cert.PKIXCertPathBuilderResult
import java.security.cert.TrustAnchor
import java.security.cert.X509CertSelector
import java.security.cert.X509Certificate
import java.util.Collections
import javax.security.auth.x500.X500Principal
import org.jmrtd.cert.CVCPrincipal
import org.jmrtd.cert.CardVerifiableCertificate
import org.jmrtd.lds.icao.DG2File
import org.jmrtd.lds.icao.DG5File
import org.jmrtd.lds.iso19794.FaceImageInfo
import org.jmrtd.lds.iso19794.FaceInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider

object PassportNfcUtils {

    private val TAG = PassportNfcUtils::class.java.simpleName

    private const val IS_PKIX_REVOCATION_CHECKING_ENABLED = false

    init {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    @Throws(IOException::class)
    fun retrieveFaceImage(dg2File: DG2File, logController: LogController): Bitmap {
        val allFaceImageInfos = ArrayList<FaceImageInfo>()
        dg2File.subRecords.filterIsInstance<FaceInfo>().forEach { faceInfo ->
            allFaceImageInfos.addAll(faceInfo.faceImageInfos)
        }

        if (!allFaceImageInfos.isEmpty()) {
            val faceImageInfo = allFaceImageInfos.iterator().next()
            return toBitmap(
                faceImageInfo.imageLength,
                faceImageInfo.imageInputStream,
                faceImageInfo.mimeType,
                logController,
            )
        }
        throw IOException("Unable to decodeImage FaceImage")
    }

    data class RawImageData(
        val imageBytes: ByteArray,
        val mimeType: String,
        val imageLength: Int,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as RawImageData

            if (imageLength != other.imageLength) return false
            if (!imageBytes.contentEquals(other.imageBytes)) return false
            if (mimeType != other.mimeType) return false

            return true
        }

        override fun hashCode(): Int {
            var result = imageLength
            result = 31 * result + imageBytes.contentHashCode()
            result = 31 * result + mimeType.hashCode()
            return result
        }
    }

    @Throws(IOException::class)
    fun retrieveFaceImageRaw(dg2File: DG2File): RawImageData {
        val allFaceImageInfos = ArrayList<FaceImageInfo>()
        dg2File.subRecords.filterIsInstance<FaceInfo>().forEach { faceInfo ->
            allFaceImageInfos.addAll(faceInfo.faceImageInfos)
        }

        if (!allFaceImageInfos.isEmpty()) {
            val faceImageInfo = allFaceImageInfos.iterator().next()
            val dataInputStream = DataInputStream(faceImageInfo.imageInputStream)
            val buffer = ByteArray(faceImageInfo.imageLength)
            dataInputStream.readFully(buffer, 0, faceImageInfo.imageLength)

            return RawImageData(
                imageBytes = buffer,
                mimeType = faceImageInfo.mimeType,
                imageLength = faceImageInfo.imageLength
            )
        }
        throw IOException("Unable to retrieve raw FaceImage")
    }

    @Throws(IOException::class)
    fun retrievePortraitImage(dg5File: DG5File, logController: LogController): Bitmap {
        val faceInfos = dg5File.images
        if (!faceInfos.isEmpty()) {
            val faceImageInfo = faceInfos.iterator().next()
            return toBitmap(
                faceImageInfo.imageLength,
                faceImageInfo.imageInputStream,
                faceImageInfo.mimeType,
                logController,
            )
        }
        throw IOException("Unable to decodeImage PortraitImage")
    }

    @Throws(IOException::class)
    private fun toBitmap(
        imageLength: Int,
        inputStream: InputStream,
        mimeType: String,
        logController: LogController,
    ): Bitmap {
        val dataInputStream = DataInputStream(inputStream)
        val buffer = ByteArray(imageLength)
        dataInputStream.readFully(buffer, 0, imageLength)
        val byteArrayInputStream = ByteArrayInputStream(buffer, 0, imageLength)
        return ImageUtils.decodeImage(byteArrayInputStream, imageLength, mimeType, logController)
    }

    @Throws(GeneralSecurityException::class)
    fun getEACCredentials(
        caReference: CVCPrincipal,
        cvcaStores: List<KeyStore>,
        logController: LogController,
    ): EACCredentials? {
        for (cvcaStore in cvcaStores) {
            val eacCredentials = getEACCredentials(caReference, cvcaStore, logController)
            if (eacCredentials != null) {
                return eacCredentials
            }
        }
        return null
    }

    /**
     * Searches the key store for a relevant terminal key and associated certificate chain.
     *
     * @param caReference
     * @param cvcaStore should contain a single key with certificate chain
     * @return
     * @throws GeneralSecurityException
     */
    @Throws(GeneralSecurityException::class)
    private fun getEACCredentials(
        caReference: CVCPrincipal?,
        cvcaStore: KeyStore,
        logController: LogController,
    ): EACCredentials? {
        if (caReference == null) {
            throw IllegalArgumentException("CA reference cannot be null")
        }

        var privateKey: PrivateKey?
        var chain: Array<Certificate>? = null

        val aliases = Collections.list(cvcaStore.aliases())
        for (alias in aliases) {
            if (cvcaStore.isKeyEntry(alias)) {
                val key = cvcaStore.getKey(alias, "".toCharArray())
                if (key is PrivateKey) {
                    privateKey = key
                } else {
                    logController.d(TAG) { "skipping non-private key $alias" }
                    continue
                }
                chain = cvcaStore.getCertificateChain(alias)
                return EACCredentials(privateKey, chain!!)
            } else if (cvcaStore.isCertificateEntry(alias)) {
                val certificate = cvcaStore.getCertificate(alias) as CardVerifiableCertificate
                val authRef = certificate.authorityReference
                val holderRef = certificate.holderReference
                if (caReference != authRef) {
                    continue
                }
                /* See if we have a private key for that certificate. */
                privateKey = cvcaStore.getKey(holderRef.name, "".toCharArray()) as PrivateKey
                chain = cvcaStore.getCertificateChain(holderRef.name)
                logController.d(TAG) { "found a key for holder ${holderRef.name}" }
                return EACCredentials(privateKey, chain!!)
            }
            logController.d(TAG) {
                "null chain or key for entry $alias: chain = ${chain.contentToString()}"
            }
            continue
        }
        return null
    }

    /**
     * Builds a certificate chain to an anchor using the PKIX algorithm.
     *
     * @param docSigningCertificate the start certificate
     * @param sodIssuer the issuer of the start certificate (ignored unless `docSigningCertificate` is `null`)
     * @param sodSerialNumber the serial number of the start certificate (ignored unless `docSigningCertificate` is `null`)
     *
     * @return the certificate chain
     */
    fun getCertificateChain(
        docSigningCertificate: X509Certificate?,
        sodIssuer: X500Principal,
        sodSerialNumber: BigInteger,
        cscaStores: List<CertStore>,
        cscaTrustAnchors: Set<TrustAnchor>,
        logController: LogController,
    ): List<Certificate> {
        val chain = ArrayList<Certificate>()
        val selector = X509CertSelector()
        try {

            if (docSigningCertificate != null) {
                selector.certificate = docSigningCertificate
            } else {
                selector.issuer = sodIssuer
                selector.serialNumber = sodSerialNumber
            }

            val docStoreParams =
                CollectionCertStoreParameters(setOf(docSigningCertificate as Certificate))
            val docStore = CertStore.getInstance("Collection", docStoreParams)

            val builder = CertPathBuilder.getInstance("PKIX", "BC")
            val buildParams = PKIXBuilderParameters(cscaTrustAnchors, selector)
            buildParams.addCertStore(docStore)
            for (trustStore in cscaStores) {
                buildParams.addCertStore(trustStore)
            }
            buildParams.isRevocationEnabled =
                IS_PKIX_REVOCATION_CHECKING_ENABLED /* NOTE: set to false for checking disabled. */

            var result: PKIXCertPathBuilderResult? = null

            try {
                result = builder.build(buildParams) as PKIXCertPathBuilderResult
            } catch (_: CertPathBuilderException) {
                /* NOTE: ignore, result remain null */
            }

            if (result != null) {
                val pkixCertPath = result.certPath
                if (pkixCertPath != null) {
                    chain.addAll(pkixCertPath.certificates)
                }
            }
            if (!chain.contains(docSigningCertificate)) {
                /* NOTE: if doc signing certificate not in list, we add it ourselves. */
                logController.w(TAG) { "Adding doc signing certificate after PKIXBuilder finished" }
                chain.add(0, docSigningCertificate)
            }
            if (result != null) {
                val trustAnchorCertificate = result.trustAnchor.trustedCert
                if (trustAnchorCertificate != null && !chain.contains(trustAnchorCertificate)) {
                    /* NOTE: if trust anchor not in list, we add it ourselves. */
                    logController.w(TAG) {
                        "Adding trust anchor certificate after PKIXBuilder finished"
                    }
                    chain.add(trustAnchorCertificate)
                }
            }
        } catch (e: Exception) {
            logController.e(TAG, e) { "Building a chain failed" }
        }

        return chain
    }
}
