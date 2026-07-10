/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2013  The JMRTD team
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

package org.jmrtd

import java.security.InvalidAlgorithmParameterException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.Security
import java.security.cert.CertStore
import java.security.cert.CertStoreException
import java.security.cert.Certificate
import java.security.cert.TrustAnchor
import java.security.cert.X509CertSelector
import java.security.cert.X509Certificate
import org.bouncycastle.jce.provider.BouncyCastleProvider

/**
 * Provides lookup for certificates, keys, CRLs used in
 * document validation and access control for data groups.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: $
 */
class MRTDTrustStore
/**
 * Constructs an instance.
 *
 * @param cscaAnchors the root certificates for document validation
 * @param cscaStores the certificates used in document validation
 * @param cvcaStores the certificates used for access to EAC protected data groups
 */
@JvmOverloads constructor(
    var cscaAnchors: MutableSet<TrustAnchor>? = HashSet(),
    var cscaStores: MutableList<CertStore>? = ArrayList(),
    var cvcaStores: MutableList<KeyStore>? = ArrayList()
) {

    /**
     * Adds root certificates for document validation.
     *
     * @param trustAnchors a collection of trustAnchors
     */
    fun addCSCAAnchors(trustAnchors: Collection<TrustAnchor>) {
        cscaAnchors!!.addAll(trustAnchors)
    }


    /**
     * Adds a certificate store for document validation.
     *
     * @param certStore the certificate store
     */
    fun addCSCAStore(certStore: CertStore) {
        cscaStores!!.add(certStore)
    }

    /* ONLY PRIVATE METHODS BELOW */

    @Throws(
        KeyStoreException::class,
        InvalidAlgorithmParameterException::class,
        NoSuchAlgorithmException::class,
        CertStoreException::class
    )
    fun addAsCSCACertStore(certStore: CertStore) {
        addCSCAStore(certStore)
        val rootCerts = certStore.getCertificates(SELF_SIGNED_X509_CERT_SELECTOR)
        addCSCAAnchors(getAsAnchors(rootCerts))
    }

    companion object {

        init {
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }

        private val SELF_SIGNED_X509_CERT_SELECTOR = object : X509CertSelector() {
            override fun match(cert: Certificate): Boolean {
                if (cert !is X509Certificate) {
                    return false
                }
                val issuer = cert.issuerX500Principal
                val subject = cert.subjectX500Principal
                return issuer == null && subject == null || subject == issuer
            }

            override fun clone(): Any {
                return this
            }
        }

        /**
         * Returns a set of trust anchors based on the X509 certificates in `certificates`.
         *
         * @param certificates a collection of X509 certificates
         *
         * @return a set of trust anchors
         */
        private fun getAsAnchors(certificates: Collection<Certificate>): Set<TrustAnchor> {
            val anchors = HashSet<TrustAnchor>(certificates.size)
            for (certificate in certificates) {
                if (certificate is X509Certificate) {
                    anchors.add(TrustAnchor(certificate, null))
                }
            }
            return anchors
        }
    }
}
