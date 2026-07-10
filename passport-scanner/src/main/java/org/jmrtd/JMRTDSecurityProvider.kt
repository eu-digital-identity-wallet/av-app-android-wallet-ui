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

import java.security.Provider
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider

/**
 * Security provider for JMRTD specific implementations.
 * Main motivation is to make JMRTD less dependent on the BouncyCastle provider.
 * Provides:
 *
 *  * [java.security.cert.CertificateFactory] &quot;CVC&quot;
 * (a factory for [org.jmrtd.cert.CardVerifiableCertificate] instances)
 *
 *  * [java.security.cert.CertStore] &quot;PKD&quot;
 * (LDAP based `CertStore`,
 * where the directory contains CSCA and document signer certificates)
 *
 *  * [java.security.cert.CertStore] &quot;JKS&quot;
 * (`KeyStore` based `CertStore`,
 * where the JKS formatted `KeyStore` contains CSCA certificates)
 *
 *  * [java.security.cert.CertStore] &quot;PKCS12&quot;
 * (`KeyStore` based `CertStore`,
 * where the PKCS#12 formatted `KeyStore` contains CSCA certificates)
 *
 *
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: $
 */
class JMRTDSecurityProvider private constructor() :
    Provider("JMRTD", 0.1, "JMRTD Security Provider") {

    init {
        put("CertificateFactory.CVC", "org.jmrtd.cert.CVCertificateFactorySpi")
        put("CertStore.PKD", "org.jmrtd.cert.PKDCertStoreSpi")
        put("CertStore.JKS", "org.jmrtd.cert.KeyStoreCertStoreSpi")
        put("CertStore.BKS", "org.jmrtd.cert.KeyStoreCertStoreSpi")
        put("CertStore.PKCS12", "org.jmrtd.cert.KeyStoreCertStoreSpi")

        /* Replicate BC algorithms... */
        replicateFromProvider("CertificateFactory", "X.509", bouncyCastleProvider)
        replicateFromProvider("CertStore", "Collection", bouncyCastleProvider)
        //			replicateFromProvider("KeyStore", "JKS", SUN_PROVIDER);
        replicateFromProvider("MessageDigest", "SHA1", bouncyCastleProvider)
        replicateFromProvider("Signature", "MD2withRSA", bouncyCastleProvider)
        replicateFromProvider("Signature", "MD4withRSA", bouncyCastleProvider)
        replicateFromProvider("Signature", "MD5withRSA", bouncyCastleProvider)
        replicateFromProvider("Signature", "SHA1withRSA", bouncyCastleProvider)
        replicateFromProvider("Signature", "SHA256withRSA", bouncyCastleProvider)
        replicateFromProvider("Signature", "SHA384withRSA", bouncyCastleProvider)
        replicateFromProvider("Signature", "SHA512withRSA", bouncyCastleProvider)
        replicateFromProvider("Signature", "SHA224withRSA", bouncyCastleProvider)

        replicateFromProvider("Signature", "SHA256withRSA/PSS", bouncyCastleProvider)

        put("Alg.Alias.Mac.ISO9797Alg3Mac", "ISO9797ALG3MAC")
        put("Alg.Alias.CertificateFactory.X509", "X.509")
    }

    private fun replicateFromProvider(
        serviceName: String,
        algorithmName: String,
        provider: Provider
    ) {
        val name = "$serviceName.$algorithmName"
        val service = provider[name]
        if (service != null) {
            put(name, service)
        }
    }

    companion object {
        private val BC_PROVIDER by lazy {
            BouncyCastleProvider()
        }
        val instance: Provider = JMRTDSecurityProvider()

        init {
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }

        /**
         * Gets the BC provider, if present.
         *
         * @return the BC provider, the SC provider, or `null`
         */
        val bouncyCastleProvider: Provider
            get() {
                return BC_PROVIDER
            }
    }
}
