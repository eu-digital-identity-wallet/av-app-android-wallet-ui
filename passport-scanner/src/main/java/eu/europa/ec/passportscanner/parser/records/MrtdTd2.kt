/*
 * Copyright (c) 2026 European Commission
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

package eu.europa.ec.passportscanner.parser.records

import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.passportscanner.parser.MrzParser
import eu.europa.ec.passportscanner.parser.MrzRange
import eu.europa.ec.passportscanner.parser.MrzRecord
import eu.europa.ec.passportscanner.parser.types.MrzFormat

/**
 * MRTD TD2 record: two lines of 36 characters (ICAO 9303 part 6), used by older ID cards
 * such as the Romanian ID card without chip. It is parsed with its check digits so that the
 * scanner can tell such a document apart from a misread one.
 */
class MrtdTd2 : MrzRecord(MrzFormat.MRTD_TD2) {
    /**
     * Optional data at the discretion of the issuing State.
     */
    var optional: String? = null

    override fun fromMrz(mrz: String, logController: LogController) {
        super.fromMrz(mrz, logController)
        val p = MrzParser(mrz, logController)
        setName(p.parseName(MrzRange(5, 36, 0)))
        documentNumber = p.parseString(MrzRange(0, 9, 1))
        validDocumentNumber = p.checkDigit(9, 1, MrzRange(0, 9, 1), "document number")
        nationality = p.parseString(MrzRange(10, 13, 1))
        dateOfBirth = p.parseDate(MrzRange(13, 19, 1))
        validDateOfBirth =
            p.checkDigit(19, 1, MrzRange(13, 19, 1), "date of birth") && dateOfBirth.isDateValid
        sex = p.parseSex(20, 1)
        expirationDate = p.parseDate(MrzRange(21, 27, 1))
        validExpirationDate = p.checkDigit(
            27,
            1,
            MrzRange(21, 27, 1),
            "expiration date"
        ) && expirationDate.isDateValid
        optional = p.parseString(MrzRange(28, 35, 1))
        validComposite = p.checkDigit(
            35,
            1,
            p.rawValue(MrzRange(0, 10, 1), MrzRange(13, 20, 1), MrzRange(21, 35, 1)),
            "mrz"
        )
    }

    override fun toString(): String {
        return "MRTD-TD2{" + super.toString() + ", optional=" + optional + '}'
    }
}
