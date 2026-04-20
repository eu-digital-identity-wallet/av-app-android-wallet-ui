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
package eu.europa.ec.passportscanner.nfc

import android.app.PendingIntent
import android.content.Intent
import android.nfc.NfcAdapter
import android.os.Build.VERSION
import android.os.Build.VERSION_CODES
import android.os.Bundle
import android.provider.Settings
import android.view.WindowManager
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.FragmentActivity
import com.google.gson.Gson
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.passportscanner.R
import eu.europa.ec.resourceslogic.R.string
import eu.europa.ec.passportscanner.SmartScannerActivity
import eu.europa.ec.passportscanner.api.ScannerConstants
import eu.europa.ec.passportscanner.api.ScannerConstants.IS_PASSPORT
import eu.europa.ec.passportscanner.nfc.passport.Passport
import org.jmrtd.lds.icao.MRZInfo
import org.koin.android.ext.android.inject


class NFCActivity : FragmentActivity(), NFCFragment.NfcFragmentListener {

    companion object {
        private val TAG = NFCActivity::class.java.simpleName
        private const val TAG_NFC = "TAG_NFC"
    }

    private val logController: LogController by inject()
    private var mrzInfo: MRZInfo? = null
    private var nfcAdapter: NfcAdapter? = null
    private var pendingIntent: PendingIntent? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        setContentView(R.layout.activity_nfc)
        val mrz = intent.getStringExtra(ScannerConstants.NFC_MRZ_STRING)
            ?: run {
                Toast.makeText(applicationContext, "Missing MRZ data", Toast.LENGTH_SHORT).show()
                finish()
                return
            }
        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        try {
            mrzInfo = MRZInfo(mrz)
        } catch (e: Exception) {
            logController.e(TAG, e)
            Toast.makeText(applicationContext, "Invalid MRZ scanned", Toast.LENGTH_SHORT).show()
            finish()
            return
        }
        showNFCFragment()
    }

    public override fun onResume() {
        super.onResume()
        // NFC foreground dispatch requires FLAG_MUTABLE so the NFC stack can inject tag extras
        val flags = if (VERSION.SDK_INT >= VERSION_CODES.S) {
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        } else PendingIntent.FLAG_UPDATE_CURRENT or 0
        if (nfcAdapter != null && nfcAdapter?.isEnabled == true) {
            pendingIntent = PendingIntent.getActivity(
                this, 0,
                Intent(this, this.javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), flags
            )
        } else checkNFC()
    }

    public override fun onNewIntent(intent: Intent) {
        if (NfcAdapter.ACTION_TAG_DISCOVERED == intent.action || NfcAdapter.ACTION_TECH_DISCOVERED == intent.action) {
            // drop NFC events
            handleIntent(intent)
        } else {
            super.onNewIntent(intent)
        }
    }

    private fun showNFCFragment() {
        if (mrzInfo != null) {
            supportFragmentManager.beginTransaction()
                .replace(
                    R.id.container,
                    NFCFragment.newInstance(
                        mrzInfo = mrzInfo
                    ), TAG_NFC
                )
                .commit()
        }
    }

    private fun checkNFC() {
        val dialog: AlertDialog.Builder = AlertDialog.Builder(this)
        dialog.setMessage(getString(string.warning_enable_nfc))
        dialog.setPositiveButton(string.label_turn_on) { _, _ ->
            val intent = Intent(Settings.ACTION_NFC_SETTINGS)
            startActivity(intent)
        }
        dialog.setNegativeButton(string.label_close) { _, _ -> }
        dialog.show()
    }

    private fun handleIntent(intent: Intent) {
        val fragmentByTag = supportFragmentManager.findFragmentByTag(TAG_NFC)
        if (fragmentByTag is NFCFragment) {
            fragmentByTag.handleNfcTag(intent)
        }
    }

    override fun onEnableNfc() {
        if (nfcAdapter != null) {
            if (nfcAdapter?.isEnabled == false) {
                showWirelessSettings()
            }
            pendingIntent?.let {
                nfcAdapter?.enableForegroundDispatch(this@NFCActivity, it, null, null)
            }
        } else {
            Toast.makeText(this, string.required_nfc_not_supported, Toast.LENGTH_LONG).show()
        }
    }

    override fun onDisableNfc() {
        val nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        nfcAdapter.disableForegroundDispatch(this)
    }

    override fun onPassportRead(passport: Passport?) {
        val nfcResult = NFCResult.formatResult(passport = passport, logController = logController)

        // Send NFC Results via Plugin
        val data = Intent()
        logController.d(TAG) { "Success from NFC -- RESULT: $nfcResult" }
        data.putExtra(SmartScannerActivity.SCANNER_RESULT, Gson().toJson(nfcResult))

        // Also add raw face image data for our custom handling
        logController.d(TAG) { "passport object: $passport" }
        logController.d(TAG) { "passport.face: ${passport?.face}" }
        logController.d(TAG) { "passport.rawFaceImageData: ${passport?.rawFaceImageData}" }

        passport?.rawFaceImageData?.let { rawImageData ->
            logController.d(TAG) {
                "Adding face image data - mime: ${rawImageData.mimeType}, " +
                        "length: ${rawImageData.imageLength}"
            }
            data.putExtra(ScannerConstants.NFC_FACE_IMAGE, rawImageData.imageBytes)
            data.putExtra(ScannerConstants.NFC_FACE_IMAGE_MIME_TYPE, rawImageData.mimeType)
            data.putExtra(ScannerConstants.NFC_FACE_IMAGE_LENGTH, rawImageData.imageLength)
        } ?: run {
            logController.w(TAG) { "No rawFaceImageData found in passport" }
        }
        data.putExtra(ScannerConstants.EXPIRY_DATE, nfcResult.dateOfExpiry)
        data.putExtra(ScannerConstants.DATE_OF_BIRTH, nfcResult.dateOfBirth)
        data.putExtra(IS_PASSPORT, true)

        setResult(RESULT_OK, data)
        finish()
    }

    override fun onCardException(cardException: Exception?) {
        cardException?.run {
            logController.e(TAG, cardException)
        }
    }

    private fun showWirelessSettings() {
        Toast.makeText(this, getString(string.warning_enable_nfc), Toast.LENGTH_SHORT).show()
        val intent = Intent(Settings.ACTION_WIRELESS_SETTINGS)
        startActivity(intent)
    }
}
