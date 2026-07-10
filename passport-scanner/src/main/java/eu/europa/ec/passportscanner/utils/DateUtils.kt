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

import android.annotation.SuppressLint
import eu.europa.ec.businesslogic.controller.log.LogController
import java.text.DateFormat
import java.text.ParseException
import java.text.SimpleDateFormat
import java.time.LocalDate
import java.util.Date
import java.util.Locale

object DateUtils {
    /**
     *  DATE THRESHOLD is for the staring year of date parsing yy -> yyyy
     *  Example:
     *      With THRESHOLD = 99, start date will be 99 years ago from present year
     *          PRESENT_YEAR = 2023
     *          LOWEST DATE = PRESENT_YEAR - THRESHOLD = 1924
     *          HIGHEST DATE = 2023
     *              240101 -> 01/01/1924
     *              230101 -> 01/01/2023
     */
    const val BIRTH_DATE_THRESHOLD = 99
    const val EXPIRY_DATE_THRESHOLD = 49

    @SuppressLint("SimpleDateFormat")
    fun formatStandardDate(
        dateString: String?,
        fromPattern: String = "yyMMdd",
        toPattern: String = "MM/dd/yyyy",
        locale: Locale? = Locale.ENGLISH,
        threshold: Int? = null,
        logController: LogController
    ): String? {
        if (fromPattern === "yyMMdd") {
            val date = stringToDate2DigitsYear(dateString, threshold, logController) ?: return null
            return dateToString(date, SimpleDateFormat(toPattern, locale))
        }

        val date =
            stringToDate(dateString, SimpleDateFormat(fromPattern), logController) ?: return null
        return dateToString(date, SimpleDateFormat(toPattern, locale))
    }

    private fun stringToDate2DigitsYear(
        dateStr: String?,
        threshold: Int? = null,
        logController: LogController
    ): Date? {
        if (dateStr == null || threshold == null) return null
        var date: Date? = null
        try {
            val sdf = SimpleDateFormat("dd/MM/yyyy")
            val startYear = LocalDate.now().minusYears(threshold.toLong()).year
            sdf.set2DigitYearStart(sdf.parse("01/01/$startYear"))
            sdf.applyPattern("yyMMdd")
            date = sdf.parse(dateStr)
        } catch (e: ParseException) {
            logController.e("DateUtils", e)
        }
        return date
    }

    private fun stringToDate(
        dateStr: String?,
        dateFormat: DateFormat,
        logController: LogController
    ): Date? {
        if (dateStr == null) return null
        var date: Date? = null
        try {
            date = dateFormat.parse(dateStr)
        } catch (e: ParseException) {
            logController.e("DateUtils", e)
        }
        return date
    }

    private fun dateToString(date: Date, dateFormat: DateFormat): String? {
        return dateFormat.format(date)
    }
}
