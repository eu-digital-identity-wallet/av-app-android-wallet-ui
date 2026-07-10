/*
 * Java parser for the MRZ records, as specified by the ICAO organization.
 * Copyright (C) 2011 Innovatrics s.r.o.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.ec.passportscanner.parser.types

import java.io.Serializable

/**
 * Holds a MRZ date type.
 * @author Martin Vysny
 */
class MrzDate : Serializable, Comparable<MrzDate?> {
    /**
     * Year, 00-99.
     *
     *
     * Note: I am unable to find a specification of conversion of this value to a full year value.
     */
    val year: Int

    /**
     * Month, 1-12.
     */
    val month: Int

    /**
     * Day, 1-31.
     */
    val day: Int


    /**
     * Returns the date validity
     * @return Returns a boolean true if the parsed date is valid, false otherwise
     */
    /**
     * Is the date valid or not
     */
    val isDateValid: Boolean

    constructor(year: Int, month: Int, day: Int) {
        this.year = year
        this.month = month
        this.day = day
        this.isDateValid = check()
    }


    override fun toString(): String {
        return "{$day/$month/$year}"
    }


    private fun check(): Boolean {
        if (year < 0 || year > 99) {
            return false
        }
        if (month < 1 || month > 12) {
            return false
        }
        if (day < 1 || day > 31) {
            return false
        }

        return true
    }

    override fun equals(other: Any?): Boolean {
        if (other == null) {
            return false
        }
        if (javaClass != other.javaClass) {
            return false
        }
        val that = other as MrzDate
        if (this.year != that.year) {
            return false
        }
        if (this.month != that.month) {
            return false
        }
        return this.day == that.day
    }

    override fun hashCode(): Int {
        var hash = 7
        hash = 11 * hash + this.year
        hash = 11 * hash + this.month
        hash = 11 * hash + this.day
        return hash
    }

    override fun compareTo(other: MrzDate?): Int {
        if (other == null) {
            return 1
        }
        return year * 10000 + month * 100 + day.compareTo(other.year * 10000 + other.month * 100 + other.day)
    }
}
