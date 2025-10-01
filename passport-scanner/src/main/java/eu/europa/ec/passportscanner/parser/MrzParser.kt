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
package eu.europa.ec.passportscanner.parser

import eu.europa.ec.passportscanner.parser.records.MrtdTd1
import eu.europa.ec.passportscanner.parser.types.MrzDate
import eu.europa.ec.passportscanner.parser.types.MrzFormat
import eu.europa.ec.passportscanner.parser.types.MrzFormat.Companion.get
import eu.europa.ec.passportscanner.parser.types.MrzSex
import eu.europa.ec.passportscanner.parser.types.MrzSex.Companion.fromMrz
import timber.log.Timber
import java.text.Normalizer
import java.util.Locale


/**
 * Parses the MRZ records.
 *
 *
 * All parse methods throws [MrzParseException] unless stated otherwise.
 * @author Martin Vysny
 */
class MrzParser(mrz: String) {
    /**
     * The MRZ record, not null.
     */
    val mrz: String?

    /**
     * The MRZ record separated into rows.
     */
    val rows: Array<String>

    /**
     * MRZ record format.
     */
    val format: MrzFormat

    /**
     * @author jllarraz@github
     * Parses the MRZ name in form of SURNAME<<FIRSTNAME></FIRSTNAME><
     * @param range the range
     * @return array of [surname, first_name], never null, always with a length of 2.
     */
    fun parseName(range: MrzRange): Array<String?> {
        checkValidCharacters(range)
        var str = rawValue(range)
        // Workaround: MLKIT sometimes reads *character `<` as either `S, C, E or K`
        // To make sure that it is not part of the name string checks begin with `<<(*)`
        // assuming that a person's name cannot have multiple different surnames.
        // Filed this issue in MLKit github: https://github.com/googlesamples/mlkit/issues/354
        var stripChar: Int
        while (str.endsWith("<") ||
            str.endsWith("<<S") ||  // Sometimes MLKit perceives `<` as `S`
            str.endsWith("<<E") ||  // Sometimes MLKit perceives `<` as `E`
            str.endsWith("<<C") ||  // Sometimes MLKit perceives `<` as `C`
            str.endsWith("<<K")
        )  // Sometimes MLKit  perceives `<` as `K`
        {
            if (str.endsWith("<<KK")) {
                stripChar = 2
            } else if (str.endsWith("<<KKK")) {
                stripChar = 3
            } else {
                stripChar = 1
            }
            str = str.substring(0, str.length - stripChar)
        }

        val names = str.split("<<".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        var surname: String?
        var givenNames = ""
        surname = parseString(MrzRange(range.column, range.column + names[0].length, range.row))
        if (names.size == 1) {
            givenNames =
                parseNameString(MrzRange(range.column, range.column + names[0].length, range.row))
            surname = ""
        } else if (names.size > 1) {
            surname =
                parseNameString(MrzRange(range.column, range.column + names[0].length, range.row))
            givenNames = parseNameString(
                MrzRange(
                    range.column + names[0].length + 2,
                    range.column + str.length,
                    range.row
                )
            )
        }
        return arrayOf<String?>(surname, givenNames)
    }

    /**
     * Returns a raw MRZ value from given range. If multiple ranges are specified, the value is concatenated.
     * @param range the ranges, not null.
     * @return raw value, never null, may be empty.
     */
    fun rawValue(vararg range: MrzRange): String {
        val sb = StringBuilder()
        for (r in range) {
            sb.append(rows[r.row].substring(r.column, r.columnTo))
        }
        return sb.toString()
    }

    /**
     * Checks that given range contains valid characters.
     * @param range the range to check.
     */
    fun checkValidCharacters(range: MrzRange) {
        val str = rawValue(range)
        for (i in 0..<str.length) {
            val c = str.get(i)
            if (c != FILLER && (c < '0' || c > '9') && (c < 'A' || c > 'Z')) {
                throw MrzParseException(
                    "Invalid character in MRZ record: " + c,
                    mrz,
                    MrzRange(range.column + i, range.column + i + 1, range.row),
                    format
                )
            }
        }
    }

    /**
     * Parses a string in given range. &lt;&lt; are replaced with ", ", &lt; is replaced by space.
     * @param range the range
     * @return parsed string.
     */
    fun parseString(range: MrzRange): String {
        checkValidCharacters(range)
        var str = rawValue(range)
        while (str.endsWith("<")) {
            str = str.substring(0, str.length - 1)
        }
        return str.replace("" + FILLER + FILLER, ", ").replace(FILLER, ' ')
    }

    /**
     * Parses a string in given range. and known characters will be replaced to numbers
     * &lt;&lt; are replaced with ", ", &lt; is replaced by space.
     * @param range the range
     * @return parsed string.
     */
    fun parseNumberString(range: MrzRange): String {
        checkValidCharacters(range)
        var str = rawValue(range)
            .replace("O", "0")
            .replace("I", "1")
            .replace("B", "8")
            .replace("S", "5")
            .replace("Z", "2")
        while (str.endsWith("<")) {
            str = str.substring(0, str.length - 1)
        }
        return str.replace("<", "").replace("" + FILLER + FILLER, ", ").replace(FILLER, ' ')
    }

    /**
     * Parses a string in given range for MRZ names. &lt;&lt; are replaced with  "",
     * &lt; is replaced by space.
     * @param range the range
     * @return parsed string.
     */
    fun parseNameString(range: MrzRange): String {
        checkValidCharacters(range)
        var str = rawValue(range)
        while (str.endsWith("<") ||
            str.endsWith("<<S") ||  // Sometimes MLKit perceives `<` as `S`
            str.endsWith("<<E") ||  // Sometimes MLKit perceives `<` as `E`
            str.endsWith("<<C") ||  // Sometimes MLKit perceives `<` as `C`
            str.endsWith("<<K") ||  // Sometimes MLKit perceives `<` as `K`
            str.endsWith("<<KK")
        )  // Sometimes MLKit perceives `<<` as `KK`
        {
            str = str.substring(0, str.length - 1)
        }
        return str.replace("" + FILLER + FILLER, "").replace(FILLER, ' ')
    }

    /**
     * Parses a string in given range for MRZ names. &lt;&lt; are replaced with  "",
     * &lt; is replaced by space.
     * @param range the range
     * @return parsed string.
     */
    fun parseNameStringWithSeparators(range: MrzRange): String {
        checkValidCharacters(range)
        var str = rawValue(range)
        while (str.endsWith("<") ||
            str.endsWith("<<S") ||  // Sometimes MLKit perceives `<` as `S`
            str.endsWith("<<E") ||  // Sometimes MLKit perceives `<` as `E`
            str.endsWith("<<C") ||  // Sometimes MLKit perceives `<` as `C`
            str.endsWith("<<CC") ||  // Sometimes MLKit perceives `<` as `C`
            str.endsWith("<<K") ||  // Sometimes MLKit perceives `<` as `K`
            str.endsWith("<<KK") ||  // Sometimes MLKit perceives `<<` as `KK`
            str.endsWith("<<KKK") ||  // Sometimes MLKit perceives `<<` as `KKK`
            str.endsWith("<<KKKK") ||  // Sometimes MLKit perceives `<<` as `KKKK`
            str.endsWith("<<KKKKK")
        )  // Sometimes MLKit perceives `<<` as `KKKKK`
        {
            str = str.substring(0, str.length - 1)
        }
        return str.replace("" + FILLER + FILLER, ", ").replace(FILLER, ' ')
    }

    /**
     * Parses a document number string in given range, &lt;&lt; are replaced with "-",
     * &lt; is replaced by space.
     *
     * @param range the range
     * @return parsed string.
     */
    fun parseDocuString(range: MrzRange): String {
        checkValidCharacters(range)
        var str = rawValue(range)
        while (str.endsWith("<")) {
            str = str.substring(0, str.length - 1)
        }
        return str.replace("" + FILLER + FILLER, "-").replace(FILLER, ' ')
    }

    /**
     * Verifies the check digit.
     * @param col the 0-based column of the check digit.
     * @param row the 0-based column of the check digit.
     * @param strRange the range for which the check digit is computed.
     * @param fieldName (optional) field name. Used only when validity check fails.
     * @return true if check digit is valid, false if not
     */
    fun checkDigit(col: Int, row: Int, strRange: MrzRange, fieldName: String?): Boolean {
        return checkDigit(col, row, rawValue(strRange), fieldName)
    }

    /**
     * Verifies the check digit.
     * @param col the 0-based column of the check digit.
     * @param row the 0-based column of the check digit.
     * @param strRange the range for which the check digit is computed.
     * @param fieldName (optional) field name. Used only when validity check fails.
     * @return true if check digit is valid, false if not
     */
    fun checkDigitWithoutFiller(
        col: Int,
        row: Int,
        strRange: MrzRange,
        fieldName: String?
    ): Boolean {
        return checkDigit(col, row, rawValue(strRange).replace("<", ""), fieldName)
    }

    /**
     * Verifies the check digit.
     * @param col the 0-based column of the check digit.
     * @param row the 0-based column of the check digit.
     * @param str the raw MRZ substring.
     * @param fieldName (optional) field name. Used only when validity check fails.
     * @return true if check digit is valid, false if not
     */
    fun checkDigit(col: Int, row: Int, str: String, fieldName: String?): Boolean {
        /*
                 * If the check digit validation fails, this will contain the location.
                 */

        var invalidCheckdigit: MrzRange? = null

        val digit: Char = (computeCheckDigit(str) + '0'.code).toChar()
        var checkDigit = rows[row].get(col)
        if (checkDigit == FILLER) {
            checkDigit = '0'
        }

        if (digit != checkDigit) {
            invalidCheckdigit = MrzRange(col, col + 1, row)
            println("Check digit verification failed for " + fieldName + ": expected " + digit + " but got " + checkDigit)
        }
        return invalidCheckdigit == null
    }

    /**
     * Parses MRZ date.
     * @param range the range containing the date, in the YYMMDD format. The range must be 6 characters long.
     * @return parsed date
     * @throws IllegalArgumentException if the range is not 6 characters long.
     */
    fun parseDate(range: MrzRange): MrzDate {
        require(range.length() == 6) { "Parameter range: invalid value " + range + ": must be 6 characters long" }
        var r: MrzRange?
        r = MrzRange(range.column, range.column + 2, range.row)
        var year: Int
        try {
            year = rawValue(r).toInt()
        } catch (ex: NumberFormatException) {
            year = -1
            Timber.d("Failed to parse MRZ date year " + rawValue(range) + ": " + ex, mrz, r)
        }
        if (year < 0 || year > 99) {
            Timber.d("Invalid year value " + year + ": must be 0..99")
        }
        r = MrzRange(range.column + 2, range.column + 4, range.row)
        var month: Int
        try {
            month = rawValue(r).toInt()
        } catch (ex: NumberFormatException) {
            month = -1
            Timber.d("Failed to parse MRZ date month " + rawValue(range) + ": " + ex, mrz, r)
        }
        if (month < 1 || month > 12) {
            Timber.d("Invalid month value " + month + ": must be 1..12")
        }
        r = MrzRange(range.column + 4, range.column + 6, range.row)
        var day: Int
        try {
            day = rawValue(r).toInt()
        } catch (ex: NumberFormatException) {
            day = -1
            Timber.d("Failed to parse MRZ date month " + rawValue(range) + ": " + ex, mrz, r)
        }
        if (day < 1 || day > 31) {
            Timber.d("Invalid day value " + day + ": must be 1..31")
        }
        return MrzDate(year, month, day)
    }

    /**
     * Parses the "sex" value from given column/row.
     * @param col the 0-based column
     * @param row the 0-based row
     * @return sex, never null.
     */
    fun parseSex(col: Int, row: Int): MrzSex {
        return fromMrz(rows[row].get(col))
    }

    /**
     * Creates new parser which parses given MRZ record.
     * @param mrz the MRZ record, not null.
     */
    init {
        this.mrz = mrz
        this.rows = mrz.split("\n".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        this.format = get(mrz)
    }

    companion object {
        // Using Timber for logging

        private val MRZ_WEIGHTS = intArrayOf(7, 3, 1)

        /**
         * Checks if given character is valid in MRZ.
         * @param c the character.
         * @return true if the character is valid, false otherwise.
         */
        private fun isValid(c: Char): Boolean {
            return ((c == FILLER) || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z'))
        }

        private fun getCharacterValue(c: Char): Int {
            if (c == FILLER) {
                return 0
            }
            if (c >= '0' && c <= '9') {
                return c.code - '0'.code
            }
            if (c >= 'A' && c <= 'Z') {
                return c.code - 'A'.code + 10
            }
            throw RuntimeException("Invalid character in MRZ record: " + c)
        }

        /**
         * Computes MRZ check digit for given string of characters.
         * @param str the string
         * @return check digit in range of 0..9, inclusive. See [MRTD documentation](http://www2.icao.int/en/MRTD/Downloads/Doc%209303/Doc%209303%20English/Doc%209303%20Part%203%20Vol%201.pdf) part 15 for details.
         */
        fun computeCheckDigit(str: String): Int {
            var result = 0
            for (i in 0..<str.length) {
                result += getCharacterValue(str.get(i)) * MRZ_WEIGHTS[i % MRZ_WEIGHTS.size]
            }
            return result % 10
        }


        /**
         * Factory method, which parses the MRZ and returns appropriate record class.
         * @param mrz MRZ to parse.
         * @return record class.
         */
        fun parse(mrz: String): MrzRecord {
            val result = get(mrz).newRecord()
            result.fromMrz(mrz)
            return result
        }

        /**
         * Factory method, which parses the MRZ and returns appropriate record class.
         * @param mrz MRZ to parse.
         * @return MrtdTd1 record class.
         */
        fun parseToMrtdTd1(mrz: String): MrtdTd1 {
            val result = get(mrz).newRecord() as MrtdTd1
            result.fromMrz(mrz)
            return result
        }



        /**
         * The filler character, '&lt;'.
         */
        const val FILLER: Char = '<'


    }
}
