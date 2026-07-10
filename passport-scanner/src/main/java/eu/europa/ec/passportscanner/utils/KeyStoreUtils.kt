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
package eu.europa.ec.passportscanner.utils

import java.io.InputStream
import java.security.KeyStore
import java.security.Security
import java.security.cert.CertStore
import java.security.cert.Certificate
import java.security.cert.CollectionCertStoreParameters
import kotlin.collections.ArrayList
import org.bouncycastle.jce.provider.BouncyCastleProvider

class KeyStoreUtils {

    fun readKeystoreFromFile(cscaInputStream: InputStream, password: String):KeyStore?{
        try{
            val keyStore: KeyStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider())
            keyStore.load(cscaInputStream, password.toCharArray())
            return keyStore
        }catch (_:java.lang.Exception) {
            return null
        }
    }

    fun toList(keyStore: KeyStore):List<Certificate>{
        val aliases = keyStore.aliases()
        val list = ArrayList<Certificate>()
        for(alias in aliases) {
            val certificate = keyStore.getCertificate(alias)
            list.add(certificate)
        }
        return list
    }

    fun toCertStore(type:String="Collection", keyStore: KeyStore): CertStore {
        return CertStore.getInstance(type, CollectionCertStoreParameters(toList(keyStore)))
    }


    companion object{
        init {
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }
}
