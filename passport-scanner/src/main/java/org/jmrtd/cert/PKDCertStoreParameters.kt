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
 *
 */

package org.jmrtd.cert

import java.security.cert.CertStoreParameters

/**
 * Parameters for PKD backed certificate store.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: $
 */
open class PKDCertStoreParameters @JvmOverloads constructor(
        /**
         * @return the serverName
         */
        val serverName: String = DEFAULT_SERVER_NAME,
        /**
         * @return the port
         */
        val port: Int = DEFAULT_PORT,
        /**
         * @return the baseDN
         */
        val baseDN: String = DEFAULT_BASE_DN) : Cloneable, CertStoreParameters {

    /**
     * Makes a copy of this object.
     *
     * @return a copy of this object
     */
    override fun clone(): Any {
        return PKDCertStoreParameters(serverName, port, baseDN)
    }

    override fun toString(): String {
        return "PKDCertStoreParameters [$serverName:$port/$baseDN]"
    }

    override fun equals(other: Any?): Boolean {
        if (other == null) {
            return false
        }
        if (other === this) {
            return true
        }
        if (this.javaClass != other.javaClass) {
            return false
        }
        val otherParams = other as PKDCertStoreParameters?
        return (otherParams!!.serverName == this.serverName
                && otherParams.port == this.port
                && otherParams.baseDN == this.baseDN)
    }

    override fun hashCode(): Int {
        return (serverName.hashCode() + port + baseDN.hashCode()) * 2 + 303
    }

    companion object {
        private const val DEFAULT_SERVER_NAME = "localhost"
        private const val DEFAULT_PORT = 389
        private const val DEFAULT_BASE_DN = "dc=data,dc=pkdDownload"
    }
}
