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

package eu.europa.ec.businesslogic.controller.storage

import eu.europa.ec.resourceslogic.provider.ResourceProvider

interface PrefsController {

    fun contains(key: String): Boolean
    fun clear(key: String)
    fun clear()
    fun setString(key: String, value: String)
    fun setLong(key: String, value: Long)
    fun setBool(key: String, value: Boolean)
    fun getString(key: String, defaultValue: String): String
    fun getLong(key: String, defaultValue: Long): Long
    fun getBool(key: String, defaultValue: Boolean): Boolean
    fun setInt(key: String, value: Int)
    fun getInt(key: String, defaultValue: Int): Int
}

class PrefsControllerImpl(
    private val resourceProvider: ResourceProvider
) : PrefsController {

    private val store: SecurePrefsStore by lazy {
        SecurePrefsStore(resourceProvider.provideContext())
    }

    override fun contains(key: String): Boolean = store.contains(key)

    override fun clear(key: String) = store.clear(key)

    override fun clear() = store.clear()

    override fun setString(key: String, value: String) = store.setString(key, value)

    override fun setLong(key: String, value: Long) = store.setLong(key, value)

    override fun setBool(key: String, value: Boolean) = store.setBool(key, value)

    override fun getString(key: String, defaultValue: String): String =
        store.getString(key, defaultValue)

    override fun getLong(key: String, defaultValue: Long): Long =
        store.getLong(key, defaultValue)

    override fun getBool(key: String, defaultValue: Boolean): Boolean =
        store.getBool(key, defaultValue)

    override fun getInt(key: String, defaultValue: Int): Int =
        store.getInt(key, defaultValue)

    override fun setInt(key: String, value: Int) = store.setInt(key, value)
}

interface PrefKeys {
    fun getCryptoAlias(): String
    fun setCryptoAlias(value: String)
    fun getCryptoKeyVersion(): Int
    fun setCryptoKeyVersion(value: Int)
    fun getPreviousCryptoAlias(): String
    fun setPreviousCryptoAlias(value: String)
    fun clearPreviousCryptoAlias()
}

class PrefKeysImpl(
    private val prefsController: PrefsController
) : PrefKeys {

    override fun getCryptoAlias(): String {
        return prefsController.getString("CryptoAlias", "")
    }

    override fun setCryptoAlias(value: String) {
        prefsController.setString("CryptoAlias", value)
    }

    override fun getCryptoKeyVersion(): Int {
        return prefsController.getInt("CryptoKeyVersion", 1)
    }

    override fun setCryptoKeyVersion(value: Int) {
        prefsController.setInt("CryptoKeyVersion", value)
    }

    override fun getPreviousCryptoAlias(): String {
        return prefsController.getString("PreviousCryptoAlias", "")
    }

    override fun setPreviousCryptoAlias(value: String) {
        prefsController.setString("PreviousCryptoAlias", value)
    }

    override fun clearPreviousCryptoAlias() {
        prefsController.clear("PreviousCryptoAlias")
    }
}
