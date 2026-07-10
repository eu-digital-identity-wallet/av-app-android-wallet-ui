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

import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.passportscanner.nfc.MAX_BLOCKSIZE
import java.io.IOException
import java.io.InputStream
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.InvalidAlgorithmParameterException
import java.security.KeyStore
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Security
import java.security.Signature
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.util.Arrays
import java.util.Collections
import java.util.Random
import java.util.TreeMap
import java.util.TreeSet
import javax.security.auth.x500.X500Principal
import net.sf.scuba.smartcards.CardServiceException
import org.jmrtd.BACKey
import org.jmrtd.FeatureStatus
import org.jmrtd.JMRTDSecurityProvider
import org.jmrtd.MRTDTrustStore
import org.jmrtd.PACEKeySpec
import org.jmrtd.PassportService
import org.jmrtd.Verdict
import org.jmrtd.VerificationStatus
import org.jmrtd.cert.CardVerifiableCertificate
import org.jmrtd.lds.AbstractTaggedLDSFile
import org.jmrtd.lds.CVCAFile
import org.jmrtd.lds.CardAccessFile
import org.jmrtd.lds.ChipAuthenticationInfo
import org.jmrtd.lds.ChipAuthenticationPublicKeyInfo
import org.jmrtd.lds.LDSFileUtil
import org.jmrtd.lds.PACEInfo
import org.jmrtd.lds.SODFile
import org.jmrtd.lds.SecurityInfo
import org.jmrtd.lds.icao.COMFile
import org.jmrtd.lds.icao.DG11File
import org.jmrtd.lds.icao.DG14File
import org.jmrtd.lds.icao.DG15File
import org.jmrtd.lds.icao.DG1File
import org.jmrtd.lds.icao.DG2File
import org.jmrtd.lds.icao.DG5File
import org.jmrtd.lds.icao.MRZInfo
import org.jmrtd.protocol.BACResult
import org.jmrtd.protocol.EACCAResult
import org.jmrtd.protocol.EACTAResult
import org.jmrtd.protocol.PACEResult

class PassportNFC @Throws(GeneralSecurityException::class)
private constructor(private val logController: LogController) {
    /** The hash function for DG hashes.  */
    private var digest: MessageDigest? = null

    /**
     * Gets the supported features (such as: BAC, AA, EAC) as
     * discovered during initialization of this document.
     *
     * @return the supported features
     *
     * @since 0.4.9
     */
    val features: FeatureStatus

    /**
     * Gets the verification status thus far.
     *
     * @return the verification status
     *
     * @since 0.4.9
     */
    val verificationStatus: VerificationStatus

    /**
     * Gets the CSCA, CVCA trust store.
     *
     * @return the trust store in use
     */
    var trustManager: MRTDTrustStore? = null

    /**
     * Gets the document signing private key, or null if not present.
     *
     * @return a private key or null
     */
    /**
     * Sets the document signing private key.
     *
     * @param docSigningPrivateKey a private key
     */
    var docSigningPrivateKey: PrivateKey? = null
        set(docSigningPrivateKey) {
            field = docSigningPrivateKey
            updateCOMSODFile(null)
        }

    private var service: PassportService? = null

    private val random: Random

    var comFile: COMFile? = null
        private set
    var sodFile: SODFile? = null
        private set
    var dg1File: DG1File? = null
        private set
    var dg2File: DG2File? = null
        private set
    var dg5File: DG5File? = null
        private set
    var dg11File: DG11File? = null
        private set
    var dg14File: DG14File? = null
        private set
    var dg15File: DG15File? = null
        private set
    var cvcaFile: CVCAFile? = null
        private set

    init {
        this.features = FeatureStatus()
        this.verificationStatus = VerificationStatus()

        this.random = SecureRandom()
    }

    /**
     * Creates a document by reading it from a service.
     *
     * @param ps the service to read from
     * @param trustManager the trust manager (CSCA, CVCA)
     * @param mrzInfo the BAC entries
     *
     * @throws CardServiceException on error
     * @throws GeneralSecurityException if certain security primitives are not supported
     */
    @Throws(CardServiceException::class, GeneralSecurityException::class)
    constructor(
        ps: PassportService?,
        trustManager: MRTDTrustStore,
        mrzInfo: MRZInfo,
        logController: LogController,
    ) : this(logController) {
        if (ps == null) {
            throw IllegalArgumentException("Service cannot be null")
        }
        this.service = ps
        this.trustManager = trustManager

        val hasSAC: Boolean
        var isSACSucceeded = false
        var paceResult: PACEResult? = null
        try {
            (service as PassportService).open()

            /* Find out whether this MRTD supports SAC. */
            try {
                logController.i(TAG) { "Inspecting card access file" }
                val cardAccessFile =
                    CardAccessFile(ps.getInputStream(PassportService.EF_CARD_ACCESS, MAX_BLOCKSIZE))
                val securityInfos = cardAccessFile.securityInfos
                for (securityInfo in securityInfos) {
                    if (securityInfo is PACEInfo) {
                        features.setSAC(Verdict.PRESENT)
                    }
                }
            } catch (e: Exception) {
                /* NOTE: No card access file, continue to test for BAC. */
                logController.e(TAG, e) { "DEBUG: failed to get card access file" }
            }

            hasSAC = features.hasSAC() == Verdict.PRESENT

            if (hasSAC) {
                try {
                    paceResult = doPACE(ps, mrzInfo)
                    isSACSucceeded = true
                } catch (e: Exception) {
                    logController.e(TAG, e) { "PACE failed, falling back to BAC" }
                    isSACSucceeded = false
                }
            }
            (service as PassportService).sendSelectApplet(isSACSucceeded)
        } catch (cse: CardServiceException) {
            throw cse
        } catch (e: Exception) {
            logController.e(TAG, e) { "Cannot open document" }
            throw CardServiceException("Cannot open document. " + e.message)
        }

        /* Find out whether this MRTD supports BAC. */
        try {
            /* Attempt to read EF.COM before BAC. */
            COMFile((service as PassportService).getInputStream(PassportService.EF_COM, MAX_BLOCKSIZE))

            if (isSACSucceeded) {
                verificationStatus.setSAC(VerificationStatus.Verdict.SUCCEEDED, "Succeeded")
                features.setBAC(Verdict.UNKNOWN)
                verificationStatus.setBAC(
                    VerificationStatus.Verdict.NOT_CHECKED,
                    "Using SAC, BAC not checked",
                    EMPTY_TRIED_BAC_ENTRY_LIST
                )
            } else {
                /* We failed SAC, and we failed BAC. */
                features.setBAC(Verdict.NOT_PRESENT)
                verificationStatus.setBAC(
                    VerificationStatus.Verdict.NOT_PRESENT,
                    "Non-BAC document",
                    EMPTY_TRIED_BAC_ENTRY_LIST
                )
            }
        } catch (e: Exception) {
            logController.e(TAG, e) {
                "Attempt to read EF.COM before BAC failed with"
            }
            features.setBAC(Verdict.PRESENT)
            verificationStatus.setBAC(
                VerificationStatus.Verdict.NOT_CHECKED,
                "BAC document",
                EMPTY_TRIED_BAC_ENTRY_LIST
            )
        }

        /* If we have to do BAC, try to do BAC. */
        val hasBAC = features.hasBAC() == Verdict.PRESENT

        if (hasBAC && !(hasSAC && isSACSucceeded)) {
            val bacKey = BACKey(mrzInfo.documentNumber, mrzInfo.dateOfBirth, mrzInfo.dateOfExpiry)
            val triedBACEntries = ArrayList<BACKey>()
            triedBACEntries.add(bacKey)
            try {
                doBAC(service as PassportService, mrzInfo)
                verificationStatus.setBAC(
                    VerificationStatus.Verdict.SUCCEEDED,
                    "BAC succeeded",
                    triedBACEntries
                )
            } catch (_: Exception) {
                verificationStatus.setBAC(
                    VerificationStatus.Verdict.FAILED,
                    "BAC failed",
                    triedBACEntries
                )
            }
        }

        /* Pre-read these files that are always present. */

        val dgNumbersAlreadyRead = TreeSet<Int>()

        try {
            comFile = getComFile(ps)
            sodFile = getSodFile(ps)
            dg1File = getDG1File(ps)
            dgNumbersAlreadyRead.add(1)
        } catch (ioe: IOException) {
            logController.w(TAG, ioe) { "Could not read file" }
        }

        try {
            dg14File = getDG14File(ps)
        } catch (e: Exception) {
            logController.w(TAG, e) { "Could not read DG14 file" }
        }

        try {
            cvcaFile = getCVCAFile(ps)
        } catch (e: Exception) {
            logController.w(TAG, e) { "Could not read CVCA file" }
        }

        /* Get the list of DGs from EF.SOd, we don't trust EF.COM. */
        val dgNumbers = ArrayList<Int>()
        val currentSodFile = sodFile
        val currentComFile = comFile
        if (currentSodFile != null) {
            dgNumbers.addAll(currentSodFile.dataGroupHashes.keys)
        } else if (currentComFile != null) {
            /* Get the list from EF.COM since we failed to parse EF.SOd. */
            logController.w(TAG) { "Failed to get DG list from EF.SOd. Getting DG list from EF.COM." }
            val tagList = currentComFile.tagList
            toDataGroupList(tagList)?.let { dgNumbers.addAll(it) }
        }
        Collections.sort(dgNumbers) /* NOTE: need to sort it, since we get keys as a set. */

        logController.d(TAG) { "Found DGs: $dgNumbers" }

        var hashResults: MutableMap<Int, VerificationStatus.HashMatchResult>? =
            verificationStatus.hashResults
        if (hashResults == null) {
            hashResults = TreeMap<Int, VerificationStatus.HashMatchResult>()
        }

        if (currentSodFile != null) {
            /* Initial hash results: we know the stored hashes, but not the computed hashes yet. */
            val storedHashes = currentSodFile.dataGroupHashes
            for (dgNumber in dgNumbers) {
                val storedHash = storedHashes[dgNumber] ?: continue
                var hashResult: VerificationStatus.HashMatchResult? = hashResults[dgNumber]
                if (hashResult != null) {
                    continue
                }
                hashResult = if (dgNumbersAlreadyRead.contains(dgNumber)) {
                    verifyHash(dgNumber)
                } else {
                    VerificationStatus.HashMatchResult(storedHash, null)
                }
                if (hashResult != null) {
                    hashResults[dgNumber] = hashResult
                }
            }
        }
        verificationStatus.setHT(
            VerificationStatus.Verdict.UNKNOWN,
            verificationStatus.htReason,
            hashResults
        )

        /* Check EAC support by DG14 presence. */
        if (dgNumbers.contains(14)) {
            features.setEAC(Verdict.PRESENT)
            features.setCA(Verdict.PRESENT)
        } else {
            features.setEAC(Verdict.NOT_PRESENT)
            features.setCA(Verdict.NOT_PRESENT)
        }

        val hasCA = features.hasCA() == Verdict.PRESENT
        if (hasCA) {
            try {
                val eaccaResults = doEACCA(ps, dg14File, sodFile)
                verificationStatus.setCA(
                    VerificationStatus.Verdict.SUCCEEDED,
                    "EAC succeeded",
                    eaccaResults[0]
                )
            } catch (_: Exception) {
                verificationStatus.setCA(VerificationStatus.Verdict.FAILED, "CA Failed", null)
            }
        }

        val hasEAC = features.hasEAC() == Verdict.PRESENT
        val cvcaKeyStores = trustManager.cvcaStores
        if (hasEAC && cvcaKeyStores != null && cvcaKeyStores.size > 0 && verificationStatus.ca == VerificationStatus.Verdict.SUCCEEDED) {
            try {
                val eactaResults = doEACTA(
                    ps,
                    mrzInfo,
                    cvcaFile,
                    paceResult,
                    verificationStatus.caResult,
                    cvcaKeyStores
                )
                verificationStatus.setEAC(
                    VerificationStatus.Verdict.SUCCEEDED,
                    "EAC succeeded",
                    eactaResults[0]
                )
            } catch (e: Exception) {
                logController.e(TAG, e) { "EAC failed" }
                verificationStatus.setEAC(VerificationStatus.Verdict.FAILED, "EAC Failed", null)
            }

            dgNumbersAlreadyRead.add(14)
        }

        /* DG15 contains public key for Active Authentication - skip AA but still read DG15 if present */
        if (dgNumbers.contains(15)) {
            try {
                dg15File = getDG15File(ps)
                dgNumbersAlreadyRead.add(15)
            } catch (ioe: IOException) {
                logController.w(TAG, ioe) { "Could not read DG15 file" }
            } catch (e: Exception) {
                logController.w(TAG, e) { "Failed to read DG15" }
            }
        }


        try {
            dg2File = getDG2File(ps)
        } catch (e: Exception) {
            logController.e(TAG, e) { "Failed to read DG2" }
        }

        try {
            dg5File = getDG5File(ps)
        } catch (e: Exception) {
            logController.e(TAG, e) { "Failed to read DG5" }
        }

        try {
            dg11File = getDG11File(ps)
        } catch (e: Exception) {
            logController.e(TAG, e) { "DG11 fail read" }
        }
    }

    /**
     * Verifies the document using the security related mechanisms.
     * Convenience method.
     *
     * @return the security status
     */
    fun verifySecurity(): VerificationStatus {
        /* NOTE: Since 0.4.9 verifyAA and verifyEAC were removed. AA is always checked as part of the prelude.
         * (EDIT: For debugging it's back here again, see below...)
         */
        /* NOTE: We could also move verifyDS and verifyCS to prelude. */
        /* NOTE: COM SOd consistency check ("Jeroen van Beek sanity check") is implicit now, we work from SOd, ignoring COM. */

        /* Verify whether the Document Signing Certificate is signed by a Trust Anchor in our CSCA store. */
        verifyCS()

        /* Verify whether hashes in EF.SOd signed with document signer certificate. */
        verifyDS()

        /* Verify hashes. */
        verifyHT()


        return verificationStatus
    }

    /**
     * Updates EF_COM and EF_SOd using a new document signing certificate.
     *
     * @param newCertificate a certificate
     */
    private fun updateCOMSODFile(newCertificate: X509Certificate?) {
        try {
            val currentSodFile = sodFile ?: return
            val currentComFile = comFile
            val digestAlg = currentSodFile.digestAlgorithm
            val signatureAlg = currentSodFile.digestEncryptionAlgorithm
            val cert = newCertificate ?: currentSodFile.docSigningCertificate
            val signature = currentSodFile.encryptedDigest
            val dgHashes = TreeMap<Int, ByteArray>()

            val dgFids = LDSFileUtil.getDataGroupNumbers(currentSodFile)
            val digest: MessageDigest = MessageDigest.getInstance(digestAlg)
            for (fid in dgFids) {
                if (fid != PassportService.EF_COM.toInt() && fid != PassportService.EF_SOD.toInt() && fid != PassportService.EF_CVCA.toInt()) {
                    val dg = getDG(fid)
                    if (dg == null) {
                        logController.w(TAG) { "Could not get input stream for $fid" }
                        continue
                    }
                    val tag = dg.encoded[0]
                    dgHashes[LDSFileUtil.lookupDataGroupNumberByTag(tag.toInt())] =
                        digest.digest(dg.encoded)
                    currentComFile?.insertTag(tag.toInt() and 0xFF)
                }
            }
            if (this.docSigningPrivateKey != null) {
                sodFile =
                    SODFile(digestAlg, signatureAlg, dgHashes, this.docSigningPrivateKey, cert)
            } else {
                sodFile = SODFile(digestAlg, signatureAlg, dgHashes, signature, cert)
            }
        } catch (e: Exception) {
            logController.e(TAG, e) { "Failed to update EF_COM and EF_SOD" }
        }
    }

    /**
     * Checks the security object's signature.
     *
     * TODO: Check the cert stores (notably PKD) to fetch document signer certificate (if not embedded in SOd) and check its validity before checking the signature.
     */
    private fun verifyDS() {
        try {
            verificationStatus.setDS(VerificationStatus.Verdict.UNKNOWN, "Unknown")
            val currentSodFile = sodFile ?: run {
                verificationStatus.setDS(VerificationStatus.Verdict.FAILED, "No SOd file")
                return
            }

            /* Check document signing signature. */
            val docSigningCert = currentSodFile.docSigningCertificate
            if (docSigningCert == null) {
                logController.w(TAG) { "Could not get document signer certificate from EF.SOd" }
            }
            if (checkDocSignature(docSigningCert)) {
                verificationStatus.setDS(VerificationStatus.Verdict.SUCCEEDED, "Signature checked")
            } else {
                verificationStatus.setDS(VerificationStatus.Verdict.FAILED, "Signature incorrect")
            }
        } catch (_: NoSuchAlgorithmException) {
            verificationStatus.setDS(
                VerificationStatus.Verdict.FAILED,
                "Unsupported signature algorithm"
            )
            return  /* NOTE: Serious enough to not perform other checks, leave method. */
        } catch (e: Exception) {
            logController.e(TAG, e) { "Failed to check document signing signature" }
            verificationStatus.setDS(VerificationStatus.Verdict.FAILED, "Unexpected exception")
            return  /* NOTE: Serious enough to not perform other checks, leave method. */
        }
    }

    /**
     * Checks the certificate chain.
     */
    private fun verifyCS() {
        try {

            val chain = ArrayList<Certificate>()

            val currentSodFile = sodFile
            if (currentSodFile == null) {
                verificationStatus.setCS(
                    VerificationStatus.Verdict.FAILED,
                    "Unable to build certificate chain",
                    chain
                )
                return
            }

            /* Get doc signing certificate and issuer info. */
            var docSigningCertificate: X509Certificate? = null
            var sodIssuer: X500Principal? = null
            var sodSerialNumber: BigInteger? = null
            try {
                sodIssuer = currentSodFile.issuerX500Principal
                sodSerialNumber = currentSodFile.serialNumber
                docSigningCertificate = currentSodFile.docSigningCertificate
            } catch (e: Exception) {
                logController.w(
                    TAG,
                    e
                ) { "Error getting document signing certificate" }
                // FIXME: search for it in cert stores?
            }

            if (docSigningCertificate != null) {
                chain.add(docSigningCertificate)
            } else {
                logController.w(TAG) { "Error getting document signing certificate from EF.SOd" }
            }

            /* Get trust anchors. */
            val cscaStores = trustManager?.cscaStores?.toList()
            if (cscaStores.isNullOrEmpty()) {
                logController.w(TAG) { "No CSCA certificate stores found." }
                verificationStatus.setCS(
                    VerificationStatus.Verdict.FAILED,
                    "No CSCA certificate stores found",
                    chain
                )
            }
            val cscaTrustAnchors = trustManager?.cscaAnchors?.toSet()
            if (cscaTrustAnchors.isNullOrEmpty()) {
                logController.w(TAG) { "No CSCA trust anchors found." }
                verificationStatus.setCS(
                    VerificationStatus.Verdict.FAILED,
                    "No CSCA trust anchors found",
                    chain
                )
            }

            /* Optional internal EF.SOd consistency check. */
            if (docSigningCertificate != null) {
                val docIssuer = docSigningCertificate.issuerX500Principal
                if (sodIssuer != null && sodIssuer != docIssuer) {
                    logController.e(TAG) {
                        "Security object issuer principal is different from embedded DS certificate issuer!"
                    }
                }
                val docSerialNumber = docSigningCertificate.serialNumber
                if (sodSerialNumber != null && sodSerialNumber != docSerialNumber) {
                    logController.w(TAG) {
                        "Security object serial number is different from embedded DS certificate serial number!"
                    }
                }
            }

            /* Run PKIX algorithm to build chain to any trust anchor. Add certificates to our chain. */
            if (sodIssuer == null || sodSerialNumber == null || cscaStores == null || cscaTrustAnchors == null) {
                verificationStatus.setCS(
                    VerificationStatus.Verdict.FAILED,
                    "Missing data to build certificate chain",
                    chain
                )
                return
            }
            val pkixChain = PassportNfcUtils.getCertificateChain(
                docSigningCertificate,
                sodIssuer,
                sodSerialNumber,
                cscaStores,
                cscaTrustAnchors,
                logController
            )

            for (certificate in pkixChain) {
                if (certificate == docSigningCertificate) {
                    continue
                } /* Ignore DS certificate, which is already in chain. */
                chain.add(certificate)
            }

            val chainDepth = chain.size
            if (chainDepth <= 1) {
                verificationStatus.setCS(
                    VerificationStatus.Verdict.FAILED,
                    "Could not build chain to trust anchor",
                    chain
                )
                return
            }
            if (verificationStatus.cs == VerificationStatus.Verdict.UNKNOWN) {
                verificationStatus.setCS(
                    VerificationStatus.Verdict.SUCCEEDED,
                    "Found a chain to a trust anchor",
                    chain
                )
            }
        } catch (e: Exception) {
            logController.e(TAG, e) { "Failed to build certificate chain" }
            verificationStatus.setCS(
                VerificationStatus.Verdict.FAILED,
                "Signature failed",
                EMPTY_CERTIFICATE_CHAIN
            )
        }
    }

    /**
     * Checks hashes in the SOd correspond to hashes we compute.
     */
    private fun verifyHT() {
        /* Compare stored hashes to computed hashes. */
        var hashResults: MutableMap<Int, VerificationStatus.HashMatchResult>? =
            verificationStatus.hashResults
        if (hashResults == null) {
            hashResults = TreeMap<Int, VerificationStatus.HashMatchResult>()
        }

        val currentSodFile = sodFile
        if (currentSodFile == null) {
            verificationStatus.setHT(VerificationStatus.Verdict.FAILED, "No SOd", hashResults)
            return
        }

        val storedHashes = currentSodFile.dataGroupHashes
        for (dgNumber in storedHashes.keys) {
            verifyHash(dgNumber, hashResults)
        }
        if (verificationStatus.ht == VerificationStatus.Verdict.UNKNOWN) {
            verificationStatus.setHT(
                VerificationStatus.Verdict.SUCCEEDED,
                "All hashes match",
                hashResults
            )
        } else {
            /* Update storedHashes and computedHashes. */
            verificationStatus.setHT(
                verificationStatus.ht ?: VerificationStatus.Verdict.UNKNOWN,
                verificationStatus.htReason,
                hashResults
            )
        }
    }

    /**
     * Read a data group content as bytes.
     *
     * @param service JMRTD Service API to communicate to the secure chip
     * @param n The Data Group Number ([1,2,11,12,15])
     *
     * @return Content of a Data Group in byte array representation
     */
    @Throws(CardServiceException::class, IOException::class)
    fun readEF(service: PassportService, n: Int): ByteArray? {

        val efdgMap = mapOf(
            1 to PassportService.EF_DG1,
            2 to PassportService.EF_DG2,
            3 to PassportService.EF_DG3,
            4 to PassportService.EF_DG4,
            5 to PassportService.EF_DG5,
            6 to PassportService.EF_DG6,
            7 to PassportService.EF_DG7,
            11 to PassportService.EF_DG11,
            12 to PassportService.EF_DG12,
            14 to PassportService.EF_DG14,
            15 to PassportService.EF_DG15,
        )

        val ef = efdgMap[n] ?: return null

        return service.getInputStream(ef, MAX_BLOCKSIZE).use { dgInputStream ->
            val buf = ByteArray(dgInputStream.length)
            var qb: Int
            var i = 0
            while (dgInputStream.read().also { qb = it } != -1) {
                buf[i] = qb.toByte()
                i++
            }
            buf.copyOfRange(0, i)
        }
    }

    private fun verifyHash(dgNumber: Int): VerificationStatus.HashMatchResult? {
        var hashResults: MutableMap<Int, VerificationStatus.HashMatchResult>? =
            verificationStatus.hashResults
        if (hashResults == null) {
            hashResults = TreeMap<Int, VerificationStatus.HashMatchResult>()
        }
        return verifyHash(dgNumber, hashResults)
    }

    /**
     * Verifies the hash for the given datagroup.
     * Note that this will block until all bytes of the datagroup
     * are loaded.
     *
     * @param dgNumber
     *
     * @param hashResults the hashtable status to update
     */
    private fun verifyHash(
        dgNumber: Int,
        hashResults: MutableMap<Int, VerificationStatus.HashMatchResult>,
    ): VerificationStatus.HashMatchResult? {
        val fid = LDSFileUtil.lookupFIDByTag(LDSFileUtil.lookupTagByDataGroupNumber(dgNumber))
        val currentSodFile = sodFile ?: run {
            verificationStatus.setHT(VerificationStatus.Verdict.FAILED, "No SOd", hashResults)
            return null
        }
        val currentService = service ?: return null

        /* Get the stored hash for the DG. */
        val storedHash: ByteArray
        try {
            val storedHashes = currentSodFile.dataGroupHashes
            storedHash = storedHashes[dgNumber] ?: run {
                verificationStatus.setHT(
                    VerificationStatus.Verdict.FAILED,
                    "DG$dgNumber failed, no stored hash in SOD",
                    hashResults
                )
                return null
            }
        } catch (_: Exception) {
            verificationStatus.setHT(
                VerificationStatus.Verdict.FAILED,
                "DG$dgNumber failed, could not get stored hash",
                hashResults
            )
            return null
        }

        /* Initialize hash. */
        val digestAlgorithm = currentSodFile.digestAlgorithm
        try {
            digest = getDigest(digestAlgorithm)
        } catch (_: NoSuchAlgorithmException) {
            verificationStatus.setHT(
                VerificationStatus.Verdict.FAILED,
                "Unsupported algorithm \"$digestAlgorithm\"",
                null
            )
            return null // DEBUG -- MO
        }

        /* Read the DG. */
        var dgBytes: ByteArray? = null
        try {
            val abstractTaggedLDSFile = getDG(dgNumber)
            if (abstractTaggedLDSFile != null) {
                dgBytes = readEF(currentService, dgNumber)
            }

            if (abstractTaggedLDSFile == null && verificationStatus.eac != VerificationStatus.Verdict.SUCCEEDED && (fid == PassportService.EF_DG3 || fid == PassportService.EF_DG4)) {
                logController.w(TAG) { "Skipping DG$dgNumber during HT verification because EAC failed." }
                val hashResult = VerificationStatus.HashMatchResult(storedHash, null)
                hashResults[dgNumber] = hashResult
                return hashResult
            }
            if (abstractTaggedLDSFile == null) {
                logController.w(TAG) { "Skipping DG$dgNumber during HT verification because file could not be read." }
                val hashResult = VerificationStatus.HashMatchResult(storedHash, null)
                hashResults[dgNumber] = hashResult
                return hashResult
            }
        } catch (_: Exception) {
            val hashResult = VerificationStatus.HashMatchResult(storedHash, null)
            hashResults[dgNumber] = hashResult
            verificationStatus.setHT(
                VerificationStatus.Verdict.FAILED,
                "DG$dgNumber failed due to exception",
                hashResults
            )
            return hashResult
        }

        /* Compute the hash and compare. */
        try {
            val computedHash = (digest ?: return null).digest(dgBytes ?: return null)
            val hashResult = VerificationStatus.HashMatchResult(storedHash, computedHash)
            hashResults[dgNumber] = hashResult

            if (!Arrays.equals(storedHash, computedHash)) {
                verificationStatus.setHT(
                    VerificationStatus.Verdict.FAILED,
                    "Hash mismatch",
                    hashResults
                )
            }

            return hashResult
        } catch (_: Exception) {
            val hashResult = VerificationStatus.HashMatchResult(storedHash, null)
            hashResults[dgNumber] = hashResult
            verificationStatus.setHT(
                VerificationStatus.Verdict.FAILED,
                "Hash failed due to exception",
                hashResults
            )
            return hashResult
        }
    }

    @Throws(NoSuchAlgorithmException::class)
    private fun getDigest(digestAlgorithm: String): MessageDigest? {
        digest?.let {
            it.reset()
            return it
        }
        logController.d(TAG) { "Using hash algorithm $digestAlgorithm" }
        if (Security.getAlgorithms("MessageDigest").contains(digestAlgorithm)) {
            digest = MessageDigest.getInstance(digestAlgorithm)
        } else {
            digest = MessageDigest.getInstance(digestAlgorithm, BC_PROVIDER)
        }
        return digest
    }

    private fun getDG(dg: Int): AbstractTaggedLDSFile? {
        when (dg) {
            1 -> {
                return dg1File
            }

            2 -> {
                return dg2File
            }

            5 -> {
                return dg5File
            }

            11 -> {
                return dg11File
            }

            14 -> {
                return dg14File
            }

            15 -> {
                return dg15File
            }

            else -> {
                return null
            }
        }
    }

    /**
     * Verifies the signature over the contents of the security object.
     * Clients can also use the accessors of this class and check the
     * validity of the signature for themselves.
     *
     * See RFC 3369, Cryptographic Message Syntax, August 2002,
     * Section 5.4 for details.
     *
     * @param docSigningCert the certificate to use
     * (should be X509 certificate)
     *
     * @return status of the verification
     *
     * @throws GeneralSecurityException if something goes wrong
     */
    /* FIXME: move this out of lds package. */
    @Throws(GeneralSecurityException::class)
    private fun checkDocSignature(docSigningCert: Certificate?): Boolean {
        val currentSodFile = sodFile ?: return false
        val eContent = currentSodFile.eContent
        val signature = currentSodFile.encryptedDigest

        var digestEncryptionAlgorithm = try {
            currentSodFile.digestEncryptionAlgorithm
        } catch (_: Exception) {
            null
        }

        /*
         * For the cases where the signature is simply a digest (haven't seen a passport like this,
         * thus this is guessing)
         */
        if (digestEncryptionAlgorithm == null) {
            val digestAlg = currentSodFile.signerInfoDigestAlgorithm
            var digest: MessageDigest
            try {
                digest = MessageDigest.getInstance(digestAlg)
            } catch (_: Exception) {
                digest = MessageDigest.getInstance(digestAlg, BC_PROVIDER)
            }

            digest.update(eContent)
            val digestBytes = digest.digest()
            return digestBytes.contentEquals(signature)
        }

        /* For RSA_SA_PSS
         *    1. the default hash is SHA1,
         *    2. The hash id is not encoded in OID
         * So it has to be specified "manually".
         */
        if ("SSAwithRSA/PSS" == digestEncryptionAlgorithm) {
            val digestAlg = currentSodFile.signerInfoDigestAlgorithm
            digestEncryptionAlgorithm = digestAlg.replace("-", "") + "withRSA/PSS"
        }

        if ("RSA" == digestEncryptionAlgorithm) {
            val digestJavaString = currentSodFile.signerInfoDigestAlgorithm
            digestEncryptionAlgorithm = digestJavaString.replace("-", "") + "withRSA"
        }

        logController.d(TAG) { "digestEncryptionAlgorithm = $digestEncryptionAlgorithm" }

        val sig: Signature = Signature.getInstance(digestEncryptionAlgorithm, BC_PROVIDER)
        if (digestEncryptionAlgorithm.endsWith("withRSA/PSS")) {
            val saltLength = findSaltRsaPss(
                digestEncryptionAlgorithm,
                docSigningCert,
                eContent,
                signature
            )//Unknown salt so we try multiples until we get a success or failure
            val mgf1ParameterSpec = MGF1ParameterSpec("SHA-256")
            val pssParameterSpec =
                PSSParameterSpec("SHA-256", "MGF1", mgf1ParameterSpec, saltLength, 1)
            sig.setParameter(pssParameterSpec)
        }
        sig.initVerify(docSigningCert)
        sig.update(eContent)
        return sig.verify(signature)
    }

    private fun findSaltRsaPss(
        digestEncryptionAlgorithm: String,
        docSigningCert: Certificate?,
        eContent: ByteArray,
        signature: ByteArray,
    ): Int {
        //Using brute force
        for (i in 0..512) {
            try {

                val sig: Signature = Signature.getInstance(digestEncryptionAlgorithm, BC_PROVIDER)
                if (digestEncryptionAlgorithm.endsWith("withRSA/PSS")) {
                    val mgf1ParameterSpec = MGF1ParameterSpec("SHA-256")
                    val pssParameterSpec =
                        PSSParameterSpec("SHA-256", "MGF1", mgf1ParameterSpec, i, 1)
                    sig.setParameter(pssParameterSpec)
                }

                sig.initVerify(docSigningCert)
                sig.update(eContent)
                val verify = sig.verify(signature)
                if (verify) {
                    return i
                }
            } catch (e: Exception) {
                if (e is InvalidAlgorithmParameterException) {
                    logController.w(TAG) { "findSaltRsaPss: Invalid param with salt value: $i (${e.javaClass.simpleName})" }
                    continue
                } else {
                    logController.e(TAG) { "findSaltRSA_PSS: signature verification failed (${e.javaClass.simpleName})" }
                }
            }
        }
        return 0//Unable to find it
    }

    @Throws(IOException::class, CardServiceException::class, GeneralSecurityException::class)
    private fun doPACE(ps: PassportService, mrzInfo: MRZInfo): PACEResult? {
        var paceResult: PACEResult? = null
        var isCardAccessFile: InputStream? = null
        try {
            val bacKey = BACKey(mrzInfo.documentNumber, mrzInfo.dateOfBirth, mrzInfo.dateOfExpiry)
            val paceKeySpec = PACEKeySpec.createMRZKey(bacKey)
            isCardAccessFile = ps.getInputStream(PassportService.EF_CARD_ACCESS, MAX_BLOCKSIZE)

            val cardAccessFile = CardAccessFile(isCardAccessFile)
            val securityInfos = cardAccessFile.securityInfos
            val securityInfo = securityInfos.iterator().next()
            val paceInfos = ArrayList<PACEInfo>()
            if (securityInfo is PACEInfo) {
                paceInfos.add(securityInfo)
            }

            if (paceInfos.isNotEmpty()) {
                val paceInfo = paceInfos.iterator().next()
                paceResult = ps.doPACE(
                    paceKeySpec,
                    paceInfo.objectIdentifier,
                    PACEInfo.toParameterSpec(paceInfo.parameterId),
                    null
                )
            }
        } finally {
            isCardAccessFile?.close()
        }
        return paceResult
    }

    @Throws(CardServiceException::class)
    private fun doBAC(ps: PassportService, mrzInfo: MRZInfo): BACResult {
        val bacKey = BACKey(mrzInfo.documentNumber, mrzInfo.dateOfBirth, mrzInfo.dateOfExpiry)
        return ps.doBAC(bacKey)
    }

    private data class SecurityInfoData(
        val chipAuthenticationInfo: ChipAuthenticationInfo?,
        val chipAuthenticationPublicKeyInfos: List<ChipAuthenticationPublicKeyInfo>,
    )

    private fun parseSecurityInfos(dg14File: DG14File): SecurityInfoData {
        var chipAuthenticationInfo: ChipAuthenticationInfo? = null
        val chipAuthenticationPublicKeyInfos = ArrayList<ChipAuthenticationPublicKeyInfo>()

        for (securityInfo in dg14File.securityInfos) {
            when (securityInfo) {
                is ChipAuthenticationInfo -> {
                    logController.i(TAG) { "doEACCA: found ChipAuthenticationInfo" }
                    chipAuthenticationInfo = securityInfo
                }

                is ChipAuthenticationPublicKeyInfo -> {
                    logController.i(TAG) { "doEACCA: found ChipAuthenticationPublicKeyInfo" }
                    chipAuthenticationPublicKeyInfos.add(securityInfo)
                }
            }
        }

        return SecurityInfoData(chipAuthenticationInfo, chipAuthenticationPublicKeyInfos)
    }

    private fun tryAuthenticationWithInfo(
        ps: PassportService,
        chipAuthenticationInfo: ChipAuthenticationInfo,
        publicKeyInfo: ChipAuthenticationPublicKeyInfo,
    ): EACCAResult? {
        return try {
            val keyid = chipAuthenticationInfo.keyId
            val oidasn1 = chipAuthenticationInfo.objectIdentifier
            val oidhumanreadable = chipAuthenticationInfo.protocolOIDString

            logController.i("EMRTD") { "Chip Authentication starting" }
            val result = ps.doEACCA(
                keyid,
                oidasn1,
                oidhumanreadable,
                publicKeyInfo.subjectPublicKey
            )
            logController.i("EMRTD") { "Chip Authentication succeeded" }
            result
        } catch (e: CardServiceException) {
            logController.w(TAG, e) { "Authentication with ChipAuthenticationInfo failed, try next public key" }
            null
        }
    }

    private fun tryECDHAuthentication(
        ps: PassportService,
        publicKeyInfo: ChipAuthenticationPublicKeyInfo,
    ): EACCAResult? {
        val oidmapECDH = mapOf(
            SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC to "id-CA-ECDH-3DES-CBC-CBC",
            SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128 to "id-CA-ECDH-AES-CBC-CMAC-128",
            SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_192 to "id-CA-ECDH-AES-CBC-CMAC-192",
            SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256 to "id-CA-ECDH-AES-CBC-CMAC-256"
        )

        val keyid = publicKeyInfo.keyId

        for ((asn1, humanreadable) in oidmapECDH) {
            logController.d(TAG) { "trying human readable $humanreadable" }
            try {
                val result = ps.doEACCA(
                    keyid,
                    asn1,
                    humanreadable,
                    publicKeyInfo.subjectPublicKey
                )
                logController.d(TAG) { "Success" }
                return result
            } catch (cse: CardServiceException) {
                logController.e(TAG, cse) { "FAIL" }
            } catch (e: Exception) {
                logController.e(TAG, e) { "FAiL" }
            }
        }

        logController.e(TAG) { "all ECDH choices failed" }
        return null
    }

    private fun tryDHAuthentication(
        ps: PassportService,
        publicKeyInfo: ChipAuthenticationPublicKeyInfo,
    ): EACCAResult? {
        val oidmapDH = mapOf(
            SecurityInfo.ID_CA_DH_3DES_CBC_CBC to "id-CA-DH-3DES-CBC-CBC",
            SecurityInfo.ID_CA_DH_AES_CBC_CMAC_128 to "id-CA-DH-AES-CBC-CMAC-128",
            SecurityInfo.ID_CA_DH_AES_CBC_CMAC_192 to "id-CA-DH-AES-CBC-CMAC-192",
            SecurityInfo.ID_CA_DH_AES_CBC_CMAC_256 to "id-CA-DH-AES-CBC-CMAC-256"
        )

        val keyid = publicKeyInfo.keyId

        for ((asn1, humanreadable) in oidmapDH) {
            logController.d(TAG) { "trying human readable $humanreadable" }
            try {
                val result = ps.doEACCA(
                    keyid,
                    asn1,
                    humanreadable,
                    publicKeyInfo.subjectPublicKey
                )
                logController.d(TAG) { "Success" }
                return result
            } catch (cse: CardServiceException) {
                logController.e(TAG, cse) { "FAIL" }
            } catch (e: Exception) {
                logController.e(TAG, e) { "FAiL" }
            }
        }

        logController.e(TAG) { "all DH choices failed" }
        return null
    }

    private fun processPublicKeyInfo(
        ps: PassportService,
        publicKeyInfo: ChipAuthenticationPublicKeyInfo,
        chipAuthenticationInfo: ChipAuthenticationInfo?,
    ): EACCAResult? {
        if (chipAuthenticationInfo != null) {
            return tryAuthenticationWithInfo(ps, chipAuthenticationInfo, publicKeyInfo)
        }

        val oidasn1 = publicKeyInfo.objectIdentifier

        return when {
            SecurityInfo.ID_PK_ECDH == oidasn1 -> tryECDHAuthentication(ps, publicKeyInfo)
            SecurityInfo.ID_PK_DH == oidasn1 -> tryDHAuthentication(ps, publicKeyInfo)
            else -> {
                if (logController.isDebugLogging()) {
                    logController.d(TAG) { "UNKNOWN Security Info: $oidasn1" }
                } else {
                    logController.e(TAG) { "UNKNOWN Security Info" }
                }
                null
            }
        }
    }

    @Suppress("")
    private fun doEACCA(
        ps: PassportService,
        dg14File: DG14File?,
        sodFile: SODFile?,
    ): List<EACCAResult> {
        logController.i(TAG) { "doEACCA entry" }
        if (dg14File == null) {
            throw NullPointerException("dg14File is null")
        }

        if (sodFile == null) {
            throw NullPointerException("sodFile is null")
        }

        val eaccaResults = ArrayList<EACCAResult>()
        val securityInfoData = parseSecurityInfos(dg14File)

        for (publicKeyInfo in securityInfoData.chipAuthenticationPublicKeyInfos) {
            val result = processPublicKeyInfo(
                ps,
                publicKeyInfo,
                securityInfoData.chipAuthenticationInfo
            )
            if (result != null) {
                eaccaResults.add(result)
                break
            }
        }

        logController.i(TAG) { "doEACCA exit" }
        return eaccaResults
    }

    @Throws(
        IOException::class,
        CardServiceException::class,
        GeneralSecurityException::class,
        IllegalArgumentException::class,
        NullPointerException::class
    )
    private fun doEACTA(
        ps: PassportService,
        mrzInfo: MRZInfo,
        cvcaFile: CVCAFile?,
        paceResult: PACEResult?,
        eaccaResult: EACCAResult?,
        cvcaKeyStores: List<KeyStore>,
    ): List<EACTAResult> {
        if (cvcaFile == null) {
            throw NullPointerException("CVCAFile is null")
        }

        if (eaccaResult == null) {
            throw NullPointerException("EACCAResult is null")
        }

        val eactaResults = ArrayList<EACTAResult>()
        val possibleCVCAReferences = arrayOf(cvcaFile.caReference, cvcaFile.altCAReference)

        //EAC
        for (caReference in possibleCVCAReferences) {
            val eacCredentials =
                PassportNfcUtils.getEACCredentials(caReference, cvcaKeyStores, logController)
                    ?: continue

            val privateKey = eacCredentials.privateKey
            val chain = eacCredentials.chain
            val terminalCerts = ArrayList<CardVerifiableCertificate>(chain.size)
            for (c in chain) {
                terminalCerts.add(c as CardVerifiableCertificate)
            }

            try {
                if (paceResult == null) {
                    val eactaResult = ps.doEACTA(
                        caReference,
                        terminalCerts,
                        privateKey,
                        null,
                        eaccaResult,
                        mrzInfo.documentNumber
                    )
                    eactaResults.add(eactaResult)
                } else {
                    val eactaResult = ps.doEACTA(
                        caReference,
                        terminalCerts,
                        privateKey,
                        null,
                        eaccaResult,
                        paceResult
                    )
                    eactaResults.add(eactaResult)
                }
            } catch (cse: CardServiceException) {
                logController.e(TAG, cse) { "doEACTA failed" }
                /* NOTE: Failed? Too bad, try next public key. */
                continue
            }

            break
        }

        return eactaResults
    }

    @Throws(CardServiceException::class, IOException::class)
    private fun getComFile(ps: PassportService): COMFile {
        var isComFile: InputStream? = null
        try {
            isComFile = ps.getInputStream(PassportService.EF_COM, MAX_BLOCKSIZE)
            return readLDSFile<COMFile>(PassportService.EF_COM, isComFile)
        } finally {
            isComFile?.close()
        }
    }

    @Throws(CardServiceException::class, IOException::class)
    private fun getSodFile(ps: PassportService): SODFile {
        var isSodFile: InputStream? = null
        try {
            isSodFile = ps.getInputStream(PassportService.EF_SOD, MAX_BLOCKSIZE)
            return readLDSFile<SODFile>(PassportService.EF_SOD, isSodFile)
        } finally {
            isSodFile?.close()
        }
    }

    @Throws(CardServiceException::class, IOException::class)
    private fun getDG1File(ps: PassportService): DG1File {
        var isDG1: InputStream? = null
        try {
            isDG1 = ps.getInputStream(PassportService.EF_DG1, MAX_BLOCKSIZE)
            return readLDSFile<DG1File>(PassportService.EF_DG1, isDG1)
        } finally {
            isDG1?.close()
        }
    }

    @Throws(CardServiceException::class, IOException::class)
    private fun getDG2File(ps: PassportService): DG2File {
        var isDG2: InputStream? = null
        try {
            isDG2 = ps.getInputStream(PassportService.EF_DG2, MAX_BLOCKSIZE)
            return readLDSFile<DG2File>(PassportService.EF_DG2, isDG2)
        } finally {
            isDG2?.close()
        }
    }

    @Throws(CardServiceException::class, IOException::class)
    private fun getDG5File(ps: PassportService): DG5File {
        var isDG5: InputStream? = null
        try {
            isDG5 = ps.getInputStream(PassportService.EF_DG5, MAX_BLOCKSIZE)
            return readLDSFile(PassportService.EF_DG5, isDG5)
        } finally {
            isDG5?.close()
        }
    }

    @Throws(CardServiceException::class, IOException::class)
    private fun getDG11File(ps: PassportService): DG11File {
        var isDG11: InputStream? = null
        try {
            isDG11 = ps.getInputStream(PassportService.EF_DG11, MAX_BLOCKSIZE)
            return readLDSFile(PassportService.EF_DG11, isDG11)
        } finally {
            isDG11?.close()
        }
    }

    @Throws(CardServiceException::class, IOException::class)
    private fun getDG14File(ps: PassportService): DG14File {
        var isDG14: InputStream? = null
        try {
            isDG14 = ps.getInputStream(PassportService.EF_DG14, MAX_BLOCKSIZE)
            return readLDSFile<DG14File>(PassportService.EF_DG14, isDG14)
        } finally {
            isDG14?.close()
        }
    }

    @Throws(CardServiceException::class, IOException::class)
    private fun getDG15File(ps: PassportService): DG15File {
        var isDG15: InputStream? = null
        try {
            isDG15 = ps.getInputStream(PassportService.EF_DG15, MAX_BLOCKSIZE)
            return readLDSFile<DG15File>(PassportService.EF_DG15, isDG15)
        } finally {
            isDG15?.close()
        }
    }

    @Throws(CardServiceException::class, IOException::class)
    private fun getCVCAFile(ps: PassportService): CVCAFile {
        var isEF_CVCA: InputStream? = null
        try {
            isEF_CVCA = ps.getInputStream(PassportService.EF_CVCA, MAX_BLOCKSIZE)
            return readLDSFile<CVCAFile>(PassportService.EF_CVCA, isEF_CVCA)
        } finally {
            isEF_CVCA?.close()
        }
    }

    private fun toDataGroupList(tagList: IntArray?): List<Int>? {
        if (tagList == null) {
            return null
        }
        val dgNumberList = ArrayList<Int>(tagList.size)
        for (tag in tagList) {
            try {
                val dgNumber = LDSFileUtil.lookupDataGroupNumberByTag(tag)
                dgNumberList.add(dgNumber)
            } catch (nfe: NumberFormatException) {
                logController.w(TAG, nfe) { "Could not find DG number for tag" }
            }
        }
        return dgNumberList
    }

    companion object {

        private val TAG = PassportNFC::class.java.simpleName

        private val BC_PROVIDER = JMRTDSecurityProvider.bouncyCastleProvider

        private val EMPTY_TRIED_BAC_ENTRY_LIST = emptyList<BACKey>()
        private val EMPTY_CERTIFICATE_CHAIN = emptyList<Certificate>()

        @Suppress("UNCHECKED_CAST")
        private fun <T> readLDSFile(fid: Short, inputStream: InputStream?): T {
            return getLDSFileAsAny(fid, inputStream) as T
        }
    }
}
fun getLDSFileAsAny(fid: Short, inputStream: InputStream?): Any {
    @Suppress("INFERRED_INVISIBLE_RETURN_TYPE_WARNING")
    return LDSFileUtil.getLDSFile(fid, inputStream)
}

