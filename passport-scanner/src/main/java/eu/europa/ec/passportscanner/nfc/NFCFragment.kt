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

import android.animation.ObjectAnimator
import android.content.Context
import android.content.Intent
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.TagLostException
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.LinearInterpolator
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.browser.customtabs.CustomTabsIntent
import androidx.core.net.toUri
import androidx.fragment.app.Fragment
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.passportscanner.R
import eu.europa.ec.passportscanner.nfc.details.IntentData
import eu.europa.ec.passportscanner.nfc.details.NFCDocumentTag
import eu.europa.ec.passportscanner.nfc.passport.Passport
import eu.europa.ec.passportscanner.utils.KeyStoreUtils
import eu.europa.ec.resourceslogic.R.string
import io.reactivex.disposables.CompositeDisposable
import net.sf.scuba.smartcards.CardServiceException
import net.sf.scuba.smartcards.ISO7816
import org.jmrtd.AccessDeniedException
import org.jmrtd.BACDeniedException
import org.jmrtd.MRTDTrustStore
import org.jmrtd.PACEException
import org.jmrtd.lds.icao.MRZInfo
import org.koin.android.ext.android.inject
import org.spongycastle.jce.provider.BouncyCastleProvider
import java.io.IOException
import java.security.MessageDigest
import java.security.Security

class NFCFragment : Fragment() {

    private val logController: LogController by inject()

    private var mrzInfo: MRZInfo? = null
    private var nfcFragmentListener: NfcFragmentListener? = null
    private var textViewNfcTitle: TextView? = null
    private var textViewNfcBody: TextView? = null
    private var textViewHelpLink: TextView? = null
    private var progressBar: ProgressBar? = null
    private var mHandler = Handler(Looper.getMainLooper())
    private var disposable = CompositeDisposable()
    private var progressAnimator: ObjectAnimator? = null

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_nfc, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val arguments = arguments
        if (arguments?.containsKey(IntentData.KEY_MRZ_INFO) == true) {
            mrzInfo = arguments.getSerializable(IntentData.KEY_MRZ_INFO) as MRZInfo?
        }
        textViewNfcTitle = view.findViewById(R.id.tv_nfc_title)
        textViewNfcBody = view.findViewById(R.id.tv_nfc_body)
        textViewHelpLink = view.findViewById(R.id.tv_help_link)
        progressBar = view.findViewById(R.id.progressBar)

        // Setup help link click listener
        textViewHelpLink?.setOnClickListener {
            openHelpUrl()
        }
    }

    fun handleNfcTag(intent: Intent?) {
        if (intent == null || intent.extras == null) {
            return
        }
        val tag = intent.getParcelableExtra<Tag>(NfcAdapter.EXTRA_TAG) ?: return

        val cscaBytes = requireContext().assets.open("csca.ks").use { it.readBytes() }
        if (!verifyCscaIntegrity(cscaBytes)) {
            logController.e(TAG) { "csca.ks integrity check failed — aborting NFC read" }
            nfcFragmentListener?.onCardException(SecurityException("CSCA keystore integrity check failed"))
            return
        }
        val keyStore = KeyStoreUtils().readKeystoreFromFile(cscaBytes.inputStream(), "")

        val mrtdTrustStore = MRTDTrustStore()
        if (keyStore != null) {
            val certStore = KeyStoreUtils().toCertStore(keyStore = keyStore)
            mrtdTrustStore.addAsCSCACertStore(certStore)
        }
        val currentMrzInfo = mrzInfo ?: run {
            logController.e(TAG) { "mrzInfo is null, cannot handle NFC tag" }
            return
        }
        val subscribe = NFCDocumentTag(logController).handleTag(
            tag,
            currentMrzInfo,
            mrtdTrustStore,
            object : NFCDocumentTag.PassportCallback {

                override fun onPassportReadStart() {
                    onNFCSReadStart()
                }

                override fun onPassportReadFinish() {
                    onNFCReadFinish()
                }

                override fun onPassportRead(passport: Passport?) {
                    this@NFCFragment.onPassportRead(passport)
                }

                override fun onAccessDeniedException(exception: AccessDeniedException) {
                    Toast.makeText(
                        context,
                        getString(string.warning_authentication_failed),
                        Toast.LENGTH_SHORT
                    ).show()
                    logController.e(TAG, exception)

                    this@NFCFragment.onCardException(exception)
                }

                override fun onBACDeniedException(exception: BACDeniedException) {
                    Toast.makeText(context, exception.toString(), Toast.LENGTH_SHORT).show()
                    this@NFCFragment.onCardException(exception)
                }

                override fun onPACEException(exception: PACEException) {
                    Toast.makeText(context, exception.toString(), Toast.LENGTH_SHORT).show()
                    this@NFCFragment.onCardException(exception)
                }

                override fun onCardException(exception: CardServiceException) {
                   if (exception.cause.isTagLostReason()) {
                        this@NFCFragment.onNFCTagLost()
                        return
                    }

                    val sw = exception.sw.toShort()
                    when (sw) {
                        ISO7816.SW_CLA_NOT_SUPPORTED -> {
                            Toast.makeText(
                                context,
                                getString(string.warning_cla_not_supported),
                                Toast.LENGTH_SHORT
                            ).show()
                        }

                        else -> {
                            Toast.makeText(context, exception.toString(), Toast.LENGTH_SHORT).show()
                        }
                    }
                    this@NFCFragment.onCardException(exception)
                }

                override fun onGeneralException(exception: Exception?) {
                    Toast.makeText(context, exception?.toString(), Toast.LENGTH_SHORT).show()
                    this@NFCFragment.onCardException(exception)
                }
            })

        disposable.add(subscribe)

    }

    override fun onAttach(context: Context) {
        super.onAttach(context)
        val activity = activity
        if (activity is NfcFragmentListener) {
            nfcFragmentListener = activity
        }
    }

    override fun onDetach() {
        nfcFragmentListener = null
        super.onDetach()
    }

    override fun onResume() {
        super.onResume()
        // Set initial UI state
        textViewNfcTitle?.text = getString(string.nfc_title_initial)
        textViewNfcBody?.text = getString(string.nfc_body_initial)

        if (nfcFragmentListener != null) {
            nfcFragmentListener?.onEnableNfc()
        }
    }

    override fun onPause() {
        super.onPause()
        if (nfcFragmentListener != null) {
            nfcFragmentListener?.onDisableNfc()
        }
    }

    override fun onDestroyView() {
        if (!disposable.isDisposed) {
            disposable.dispose()
        }
        progressAnimator?.cancel()
        super.onDestroyView()
    }

    private fun onNFCSReadStart() {
        logController.d(TAG) { "onNFCSReadStart" }
        mHandler.post {
            // Update UI for reading state
            textViewNfcTitle?.text = getString(string.nfc_title_reading)
            textViewNfcBody?.text = getString(string.nfc_body_reading)
            textViewNfcBody?.gravity = android.view.Gravity.CENTER
            textViewHelpLink?.visibility = View.GONE

            // Update title padding for reading state
            val titlePaddingBottom =
                resources.getDimensionPixelSize(R.dimen.nfc_title_reading_padding_bottom)
            textViewNfcTitle?.setPadding(
                textViewNfcTitle?.paddingLeft ?: 0,
                textViewNfcTitle?.paddingTop ?: 0,
                textViewNfcTitle?.paddingRight ?: 0,
                titlePaddingBottom
            )

            // Show and animate progress bar
            progressBar?.visibility = View.VISIBLE
            progressBar?.progress = 0

            // Animate progress bar to 100% over 10 seconds
            progressAnimator = ObjectAnimator.ofInt(progressBar, "progress", 0, 100).apply {
                duration = 10000 // 10 seconds
                interpolator = LinearInterpolator()
                start()
            }
        }
    }

    private fun onNFCReadFinish() {
        logController.d(TAG) { "onNFCReadFinish" }
        mHandler.post {
            progressAnimator?.cancel()
            progressBar?.visibility = View.GONE

            // Reset UI to initial state
            textViewNfcTitle?.text = getString(string.nfc_title_initial)
            textViewNfcBody?.text = getString(string.nfc_body_initial)
            textViewNfcBody?.gravity = android.view.Gravity.START
            textViewHelpLink?.visibility = View.VISIBLE

            // Reset title padding
            val titlePaddingBottom =
                resources.getDimensionPixelSize(R.dimen.nfc_title_padding_bottom)
            textViewNfcTitle?.setPadding(
                textViewNfcTitle?.paddingLeft ?: 0,
                textViewNfcTitle?.paddingTop ?: 0,
                textViewNfcTitle?.paddingRight ?: 0,
                titlePaddingBottom
            )
        }
    }

    private fun openHelpUrl() {
        // Intentional: example.com is a template placeholder. Replace with the real help URL
        // before shipping. Do not leave example.com in production — a third party could register
        // that domain and serve attacker-controlled content in the Custom Tab.
        val helpUrl = "https://example.com/passport-help"
        try {
            val customTabsIntent = CustomTabsIntent.Builder()
                .setShowTitle(true)
                .build()
            customTabsIntent.launchUrl(requireContext(), helpUrl.toUri())
        } catch (_: Exception) {
            // Fallback to browser intent if Custom Tabs not available
            val intent = Intent(Intent.ACTION_VIEW, helpUrl.toUri())
            startActivity(intent)
        }
    }

    private fun onCardException(cardException: Exception?) {
        mHandler.post {
            if (nfcFragmentListener != null) {
                nfcFragmentListener?.onCardException(cardException)
            }
        }
    }

    private fun onNFCTagLost() {
        getString(string.nfc_error_reading_tag)
        Toast.makeText(context, "Error while NFC reading, try again", Toast.LENGTH_LONG).show()
        onNFCReadFinish()
    }

    private fun onPassportRead(passport: Passport?) {
        mHandler.post {
            if (nfcFragmentListener != null) {
                nfcFragmentListener?.onPassportRead(passport)
            }
        }
    }

    interface NfcFragmentListener {
        fun onEnableNfc()
        fun onDisableNfc()
        fun onPassportRead(passport: Passport?)
        fun onCardException(cardException: Exception?)
    }

    // SHA-256 of the shipped csca.ks asset. Update this constant whenever csca.ks is replaced.
    private fun verifyCscaIntegrity(bytes: ByteArray): Boolean {
        val expected = "c82bfd5e730d6b8b73fa7712e442ad9e7adcbfb51112e3155357a2ae5a96b8b1"
        val actual = MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }
        return actual == expected
    }

    companion object {
        private val TAG = NFCFragment::class.java.simpleName

        init {
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }

        fun newInstance(
            mrzInfo: MRZInfo?,
        ): NFCFragment {
            val myFragment = NFCFragment()
            val args = Bundle()
            args.putSerializable(IntentData.KEY_MRZ_INFO, mrzInfo)
            myFragment.arguments = args
            return myFragment
        }
    }
}

private fun Throwable?.isTagLostReason(): Boolean {
    val isTransceiveFailedCause = this?.message?.contains("Transceive failed", true) ?: false
    return this is TagLostException || (this is IOException  && isTransceiveFailedCause )
}
