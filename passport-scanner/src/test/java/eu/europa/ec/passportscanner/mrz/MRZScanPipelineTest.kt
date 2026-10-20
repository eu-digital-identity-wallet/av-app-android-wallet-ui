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

package eu.europa.ec.passportscanner.mrz

import android.graphics.Rect
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.passportscanner.mrz.MRZLineReconstructor.TextBlock
import eu.europa.ec.passportscanner.parser.MrzRecord
import eu.europa.ec.passportscanner.parser.types.MrzFormat
import eu.europa.ec.testlogic.base.TestApplication
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.mock
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Runs OCR text blocks through the same steps as [MRZAnalyzer]: line reconstruction,
 * cleaning and parsing. The MRZs are synthetic specimens with valid check digits.
 */
@RunWith(RobolectricTestRunner::class) //needed for Rect
@Config(application = TestApplication::class)
class MRZScanPipelineTest {

    private val logController: LogController = mock()

    private fun scan(vararg lines: String): MrzRecord? {
        val blocks = lines.mapIndexed { index, line ->
            TextBlock(line, Rect(0, index * 30, 300, index * 30 + 20))
        }
        val rawFullRead = MRZLineReconstructor.reconstruct(blocks)
        val cleanMrz = MRZCleaner.clean(rawFullRead, logController, skipReconstruction = true)
        return MRZCleaner.parseAndClean(cleanMrz, logController)
    }

    @Test
    fun `TD1 ID card whose surname starts with P is parsed`() {
        val record = scan(
            "IDROUAB12345671<<<<<<<<<<<<<<<",
            "9002155M3106305ROU<<<<<<<<<<<4",
            "POPESCU<<ION<<<<<<<<<<<<<<<<<<"
        )

        assertNotNull(record)
        assertEquals(MrzFormat.MRTD_TD1, record!!.format)
        assertEquals("AB1234567", record.documentNumber)
        assertEquals("POPESCU", record.surname)
    }

    @Test
    fun `TD2 ID card is recognised as TD2`() {
        val record = scan(
            "IDROUPOPESCU<<MARIA<<<<<<<<<<<<<<<<<",
            "PH123456<7ROU8001014F300101912345672"
        )

        assertNotNull(record)
        assertEquals(MrzFormat.MRTD_TD2, record!!.format)
        assertEquals("PH123456", record.documentNumber)
        assertEquals("POPESCU", record.surname)
    }

    @Test
    fun `TD2 ID card is recognised when OCR also reads a line above the MRZ`() {
        val record = scan(
            "SEMNATURA",
            "IDROUPOPESCU<<MARIA<<<<<<<<<<<<<<<<<",
            "PH123456<7ROU8001014F300101912345672"
        )

        assertNotNull(record)
        assertEquals(MrzFormat.MRTD_TD2, record!!.format)
    }

    @Test
    fun `TD2 MRZ with wrong check digits is not recognised`() {
        // Misread birth date (800101 read as 800107): check digits no longer match
        val record = scan(
            "IDROUPOPESCU<<MARIA<<<<<<<<<<<<<<<<<",
            "PH123456<7ROU8001074F300101912345672"
        )

        assertNull(record)
    }

    @Test
    fun `TD3 passport is still parsed`() {
        val record = scan(
            "P<ROUPOPESCU<<ION<<<<<<<<<<<<<<<<<<<<<<<<<<<",
            "0512345673ROU9002155M3106305<<<<<<<<<<<<<<00"
        )

        assertNotNull(record)
        assertEquals(MrzFormat.PASSPORT, record!!.format)
        assertEquals("051234567", record.documentNumber)
    }
}
