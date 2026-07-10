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
package eu.europa.ec.passportscanner.nfc.details

import android.nfc.Tag
import android.nfc.tech.IsoDep
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.passportscanner.nfc.MAX_BLOCKSIZE
import eu.europa.ec.passportscanner.nfc.passport.Passport
import eu.europa.ec.passportscanner.nfc.passport.PassportNFC
import eu.europa.ec.passportscanner.nfc.passport.PassportNfcUtils
import io.reactivex.Single
import io.reactivex.android.schedulers.AndroidSchedulers
import io.reactivex.disposables.Disposable
import io.reactivex.schedulers.Schedulers
import java.security.Security
import net.sf.scuba.smartcards.CardService
import net.sf.scuba.smartcards.CardServiceException
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.jmrtd.CardServiceProtocolException
import org.jmrtd.MRTDTrustStore
import org.jmrtd.PassportService
import org.jmrtd.VerificationStatus
import org.jmrtd.lds.icao.DG1File
import org.jmrtd.lds.icao.MRZInfo

class NFCDocumentTag(private val logController: LogController) {

    fun handleTag(
        tag: Tag,
        mrzInfo: MRZInfo,
        mrtdTrustStore: MRTDTrustStore,
        passportCallback: PassportCallback,
    ): Disposable {
        return Single.fromCallable {
            var passport: Passport? = null
            var cardServiceException: Exception? = null

            var ps: PassportService? = null
            try {
                val nfc = IsoDep.get(tag)
                nfc.timeout = 5 * 1000 //5 seconds timeout
                val cs = CardService.getInstance(nfc)
                ps = PassportService(cs, 256, MAX_BLOCKSIZE, false, true)
                ps.open()

                val passportNFC = PassportNFC(ps, mrtdTrustStore, mrzInfo, logController)
                val verifySecurity = passportNFC.verifySecurity()
                val features = passportNFC.features
                val verificationStatus = passportNFC.verificationStatus

                passport = Passport()
                passport.featureStatus = features
                passport.verificationStatus = verificationStatus
                passport.sodFile = passportNFC.sodFile

                //Passport features and verification

                //Basic Information
                if (passportNFC.dg1File != null) {
                    val info = (passportNFC.dg1File as DG1File).mrzInfo
                    passport.personDetails = PersonDetails(info.dateOfBirth, info.dateOfExpiry)
                }

                //Picture
                if (passportNFC.dg2File != null) {
                    //Get the picture
                    try {
                        val faceImage =
                            PassportNfcUtils.retrieveFaceImage(passportNFC.dg2File!!, logController)
                        passport.face = faceImage

                        // Also get the raw image data
                        val rawFaceImageData =
                            PassportNfcUtils.retrieveFaceImageRaw(passportNFC.dg2File!!)
                        passport.rawFaceImageData = rawFaceImageData
                    } catch (e: Exception) {
                        //Don't do anything
                        logController.w(TAG, e) { "Cannot read face data" }
                    }
                }

                //Portrait
                //Get the picture
                if (passportNFC.dg5File != null) {
                    //Get the picture
                    try {
                        val faceImage =
                            PassportNfcUtils.retrievePortraitImage(
                                passportNFC.dg5File!!,
                                logController
                            )
                        passport.portrait = faceImage
                    } catch (e: Exception) {
                        //Don't do anything
                        logController.w(TAG, e) { "Cannot read portrait image" }
                    }
                }

                val dg11 = passportNFC.dg11File
                if (dg11 != null) {

                    passport.additionalPersonDetails = AdditionalPersonDetails(dg11.fullDateOfBirth)

                    // Hash Checking
                    if (verifySecurity.ht != VerificationStatus.Verdict.SUCCEEDED) {
                        logController.e(TAG) { "hash-check not SUCCEEDED" }
                    }
                } else {
                    logController.e(TAG) { "DG11 is null" }
                }
            } catch (e: Exception) {
                //TODO EAC
                cardServiceException = e
            } finally {
                try {
                    ps?.close()
                } catch (ex: Exception) {
                    logController.e(TAG, ex)
                }
            }

            PassportDTO(passport, cardServiceException)

        }.doOnSubscribe {
            passportCallback.onPassportReadStart()
        }
            .subscribeOn(Schedulers.io())
            .observeOn(AndroidSchedulers.mainThread())
            .subscribe({ passportDTO ->
                if (passportDTO.cardServiceException != null) {
                    when (val cardServiceException = passportDTO.cardServiceException) {
                        is CardServiceProtocolException -> {
                            passportCallback.onCardServiceProtocolException(cardServiceException)
                        }

                        is CardServiceException -> {
                            passportCallback.onCardException(cardServiceException)
                        }

                        else -> {
                            passportCallback.onGeneralException(cardServiceException)
                        }
                    }
                } else {
                    passportCallback.onPassportRead(passportDTO.passport)
                }
                passportCallback.onPassportReadFinish()
            }, { error ->
                logController.e(TAG, error as? Exception ?: RuntimeException(error))
                passportCallback.onGeneralException(error as? Exception ?: RuntimeException(error))
                passportCallback.onPassportReadFinish()
            })
    }

    data class PassportDTO(
        val passport: Passport? = null,
        val cardServiceException: Exception? = null,
    )

    interface PassportCallback {
        fun onPassportReadStart()
        fun onPassportReadFinish()
        fun onPassportRead(passport: Passport?)
        fun onCardServiceProtocolException(exception: CardServiceProtocolException)
        fun onCardException(exception: CardServiceException)
        fun onGeneralException(exception: Exception?)
    }

    companion object {
        private val TAG = NFCDocumentTag::class.java.simpleName

        init {
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }
}
