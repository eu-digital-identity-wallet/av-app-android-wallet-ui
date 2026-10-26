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
import eu.europa.ec.passportscanner.mrz.MRZLineReconstructor.TextBlock
import eu.europa.ec.testlogic.base.TestApplication
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class) //needed for Rect
@Config(application = TestApplication::class)
class MRZLineReconstructorTest {

    private companion object {
        const val TD3_LINE_LENGTH = 44
    }

    @Test
    fun `reconstruct with empty blocks returns empty string`() {
        val result = MRZLineReconstructor.reconstruct(emptyList())

        assertEquals("", result)
    }

    @Test
    fun `reconstruct with single block non-passport returns text as-is`() {
        val blocks = listOf(
            TextBlock("IDFRATEST", Rect(0, 0, 100, 20))
        )

        val result = MRZLineReconstructor.reconstruct(blocks)

        assertEquals("IDFRATEST", result)
    }

    @Test
    fun `reconstruct with single block passport pads to TD3 length`() {
        val blocks = listOf(
            TextBlock("P<FRATEST", Rect(0, 0, 100, 20))
        )

        val result = MRZLineReconstructor.reconstruct(blocks)

        assertEquals(TD3_LINE_LENGTH, result.length)
        assertTrue(result.startsWith("P<FRATEST"))
        assertTrue(result.endsWith("<".repeat(TD3_LINE_LENGTH - 9)))
    }

    @Test
    fun `reconstruct with single block passport already at TD3 length returns as-is`() {
        // P<FRATEST<<JOHN<<DOE = 20 chars, need 24 more fillers = 44 total
        val completePassportLine = "P<FRATEST<<JOHN<<DOE" + "<".repeat(24)
        val blocks = listOf(
            TextBlock(completePassportLine, Rect(0, 0, 400, 20))
        )

        val result = MRZLineReconstructor.reconstruct(blocks)

        assertEquals(44, completePassportLine.length)
        assertEquals(completePassportLine, result)
    }

    @Test
    fun `reconstruct with 2 blocks on same line horizontal split for passport`() {
        val blocks = listOf(
            TextBlock("P<FRATEST", Rect(0, 0, 100, 20)),
            TextBlock("JOHN", Rect(200, 0, 250, 20))
        )

        val result = MRZLineReconstructor.reconstruct(blocks)

        // Should fill gap with '<' between first and second block
        assertEquals(TD3_LINE_LENGTH, result.length)
        assertTrue(result.startsWith("P<FRATEST<"))
        assertTrue(result.endsWith("JOHN"))
    }

    @Test
    fun `reconstruct with 2 blocks on different lines vertical split`() {
        val blocks = listOf(
            TextBlock("P<FRATEST", Rect(0, 0, 100, 20)),
            TextBlock("1234567890", Rect(0, 50, 100, 70))
        )

        val result = MRZLineReconstructor.reconstruct(blocks)

        val lines = result.split("\n")
        assertEquals(2, lines.size)
        assertEquals(TD3_LINE_LENGTH, lines[0].length)
        assertEquals(TD3_LINE_LENGTH, lines[1].length)
        assertTrue(lines[0].startsWith("P<FRATEST"))
        assertTrue(lines[1].startsWith("1234567890"))
    }

    @Test
    fun `reconstruct with 4 blocks in 2x2 grid for passport TD3`() {
        // Classic case: passport split into 4 blocks
        // Top-left: "P<FRATEST<<JOHN"
        // Top-right: "DOE"
        // Bottom-left: "1234567890FRA910"
        // Bottom-right: "1234567"
        val blocks = listOf(
            TextBlock("P<FRATEST<<JOHN", Rect(0, 0, 150, 20)),
            TextBlock("DOE", Rect(200, 0, 250, 20)),
            TextBlock("1234567890FRA910", Rect(0, 50, 160, 70)),
            TextBlock("1234567", Rect(200, 50, 270, 70))
        )

        val result = MRZLineReconstructor.reconstruct(blocks)

        val lines = result.split("\n")
        assertEquals(2, lines.size)

        assertEquals(TD3_LINE_LENGTH, lines[0].length)
        assertEquals(TD3_LINE_LENGTH, lines[1].length)

        assertEquals("P<FRATEST<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<DOE", lines[0])
        assertEquals("1234567890FRA910<<<<<<<<<<<<<<<<<<<<<1234567",lines[1])
    }

    @Test
    fun `reconstruct with 3 blocks - one line complete, one line split`() {
        // First line: complete in one block (44 chars)
        // Second line: split into two blocks
        val completeLine = "P<FRATEST<<JOHN<<DOE" + "<".repeat(24)  // 20 + 24 = 44 chars
        val blocks = listOf(
            TextBlock(completeLine, Rect(0, 0, 400, 20)),
            TextBlock("1234567890FRA", Rect(0, 50, 130, 70)),
            TextBlock("9101231", Rect(200, 50, 270, 70))
        )

        val result = MRZLineReconstructor.reconstruct(blocks)

        val lines = result.split("\n")
        assertEquals(2, lines.size)

        // First line should be as-is (already complete)
        assertEquals(TD3_LINE_LENGTH, completeLine.length)
        assertEquals(completeLine, lines[0])

        // Second line should be reconstructed with fillers
        assertEquals(TD3_LINE_LENGTH, lines[1].length)
        assertEquals("1234567890FRA<<<<<<<<<<<<<<<<<<<<<<<<9101231",lines[1])
    }

    @Test
    fun `reconstruct with 3 blocks - two on same line, one on different line`() {
        val blocks = listOf(
            TextBlock("P<FRATEST", Rect(0, 0, 100, 20)),
            TextBlock("JOHN", Rect(200, 0, 250, 20)),
            TextBlock("1234567890FRA9101231M<<<<<<<<<<<<<<", Rect(0, 50, 350, 70))
        )

        val result = MRZLineReconstructor.reconstruct(blocks)

        val lines = result.split("\n")
        assertEquals(2, lines.size)
        assertEquals(TD3_LINE_LENGTH, lines[0].length)
        assertEquals(TD3_LINE_LENGTH, lines[1].length)
    }

    @Test
    fun `reconstruct with 3 blocks overlapping vertically within threshold`() {
        // Blocks with Y-centers within 30% of average height should be on same line
        // height = 20, threshold  6 pixels
        val blocks = listOf(
            TextBlock("P<FRATEST", Rect(0, 0, 100, 20)),      // centerY = 10
            TextBlock("JOHN", Rect(200, 3, 250, 23)),         // centerY = 13 (within threshold)
            TextBlock("DOE", Rect(300, -2, 350, 18))          // centerY = 8 (within threshold)
        )

        val result = MRZLineReconstructor.reconstruct(blocks)

        val lines = result.split("\n")
        assertEquals(1, lines.size)
        assertEquals(TD3_LINE_LENGTH, lines[0].length)
        // All three blocks should be on same line
        assertTrue(lines[0].contains("P<FRATEST"))
        assertTrue(lines[0].contains("JOHN"))
        assertTrue(lines[0].contains("DOE"))
    }

    @Test
    fun `reconstruct with blocks beyond vertical threshold creates separate lines`() {
        // Blocks with Y-centers beyond threshold
        val blocks = listOf(
            TextBlock("P<FRATEST", Rect(0, 0, 100, 20)),      // centerY = 10
            TextBlock("1234567890", Rect(0, 40, 100, 60))     // centerY = 50 (beyond threshold)
        )

        val result = MRZLineReconstructor.reconstruct(blocks)

        val lines = result.split("\n")
        assertEquals(2, lines.size)
    }

    @Test
    fun `reconstruct with non-passport format does not pad or add fillers`() {
        // TD1 format (ID card) - doesn't start with P
        val blocks = listOf(
            TextBlock("IDFRATEST", Rect(0, 0, 100, 20)),
            TextBlock("123456", Rect(200, 0, 270, 20))
        )

        val result = MRZLineReconstructor.reconstruct(blocks)

        // Should just concatenate without fillers
        assertEquals("IDFRATEST123456", result)
    }

    @Test
    fun `reconstruct with blocks already at TD3 length does not add fillers`() {
        val blocks = listOf(
            TextBlock("P<FRATEST<<JOHN", Rect(0, 0, 150, 20)),      // 15 chars
            TextBlock("<<DOE<<<<<<<<<<<<<<<<<<<<<<<<", Rect(200, 0, 300, 20))  // 29 chars = 44 total
        )

        val result = MRZLineReconstructor.reconstruct(blocks)

        assertEquals(TD3_LINE_LENGTH, result.length)
        assertEquals("P<FRATEST<<JOHN<<DOE<<<<<<<<<<<<<<<<<<<<<<<<", result)
    }

    @Test
    fun `reconstruct with blocks exceeding TD3 length does not add fillers`() {
        val blocks = listOf(
            TextBlock("P<FRATEST<<JOHN<<DOE<<<<<<<<<<<<<<<<<<<<<<", Rect(0, 0, 400, 20)),
            TextBlock("EXTRA", Rect(450, 0, 500, 20))
        )

        val result = MRZLineReconstructor.reconstruct(blocks)

        assertTrue(result.length > TD3_LINE_LENGTH)
        assertEquals("P<FRATEST<<JOHN<<DOE<<<<<<<<<<<<<<<<<<<<<<EXTRA", result)
    }

    @Test
    fun `groupBlocksIntoLines sorts blocks top to bottom`() {
        val blocks = listOf(
            TextBlock("BOTTOM", Rect(0, 50, 100, 70)),
            TextBlock("TOP", Rect(0, 0, 100, 20)),
            TextBlock("MIDDLE", Rect(0, 25, 100, 45))
        )

        val result = MRZLineReconstructor.reconstruct(blocks)

        val lines = result.split("\n")
        // Lines should be ordered top to bottom
        assertTrue(lines[0].contains("TOP"))
        assertTrue(lines[1].contains("MIDDLE"))
        assertTrue(lines[2].contains("BOTTOM"))
    }

    @Test
    fun `groupBlocksIntoLines sorts blocks left to right within same line`() {
        val blocks = listOf(
            TextBlock("RIGHT", Rect(200, 0, 300, 20)),
            TextBlock("P<LEFT", Rect(0, 0, 100, 20)),
            TextBlock("MIDDLE", Rect(100, 0, 200, 20))
        )

        val result = MRZLineReconstructor.reconstruct(blocks)

        // Blocks should be ordered left to right: P<LEFT, MIDDLE, RIGHT
        assertTrue(result.startsWith("P<LEFT<"))
        assertTrue(result.contains("MIDDLE"))
        assertTrue(result.endsWith("RIGHT"))
    }

    @Test
    fun `reconstruct with 4 blocks in random order produces correct result`() {
        // Submit blocks in random order (not sorted)
        val blocks = listOf(
            TextBlock("9101231", Rect(200, 50, 270, 70)),      // Bottom-right (4th)
            TextBlock("P<FRATEST", Rect(0, 0, 100, 20)),       // Top-left (1st)
            TextBlock("1234567890FRA", Rect(0, 50, 130, 70)),  // Bottom-left (3rd)
            TextBlock("JOHN", Rect(200, 0, 250, 20))           // Top-right (2nd)
        )

        val result = MRZLineReconstructor.reconstruct(blocks)

        val lines = result.split("\n")
        assertEquals(2, lines.size)

        // Should still produce correct order
        assertTrue(lines[0].startsWith("P<FRATEST<"))
        assertTrue(lines[0].endsWith("JOHN"))
        assertTrue(lines[1].startsWith("1234567890FRA<"))
        assertTrue(lines[1].endsWith("9101231"))
    }

    @Test
    fun `reconstruct with minimal overlap at threshold boundary`() {
        // Test the exact boundary of 30% threshold
        val avgHeight = 20
        val exactThreshold = (avgHeight * 0.3).toInt() // 6

        val top = 0
        val bottom = 20
        val blocks = listOf(
            TextBlock("P<FRATEST", Rect(0, top, 100, 20)),           // centerY = 10
            TextBlock(
                "ATTHRESHOLD",
                Rect(0, top + exactThreshold, 100, bottom + exactThreshold)
            ),     // centerY = 16 (diff = 6, at threshold)
            TextBlock(
                "BEYONDTHRESHOLD",
                Rect(0, top + exactThreshold + 1, 100, bottom + exactThreshold + 1)
            )      // centerY = 17 (diff = 7, beyond threshold)
        )

        val result = MRZLineReconstructor.reconstruct(blocks)

        val lines = result.split("\n")
        // First two should be on same line, third on different line
        assertTrue(lines[0].contains("ATTHRESHOLD"))
        assertTrue(lines[1].contains("BEYONDTHRESHOLD"))
        assertEquals(2, lines.size)

    }

    @Test
    fun `reconstruct with single TD3 block shorter than required length gets padded`() {
        val shortText = "P<FRA"
        val blocks = listOf(
            TextBlock(shortText, Rect(0, 0, 50, 20))
        )

        val result = MRZLineReconstructor.reconstruct(blocks)

        assertEquals(TD3_LINE_LENGTH, result.length)
        assertEquals("P<FRA" + "<".repeat(TD3_LINE_LENGTH - 5), result)
    }

    @Test
    fun `reconstruct places all fillers after first block in TD3 line`() {
        // When reconstructing TD3 line, all fillers should go after first block
        val blocks = listOf(
            TextBlock("P<FRA", Rect(0, 0, 50, 20)),
            TextBlock("TEST", Rect(100, 0, 150, 20)),
            TextBlock("JOHN", Rect(200, 0, 250, 20))
        )

        val result = MRZLineReconstructor.reconstruct(blocks)

        assertEquals(TD3_LINE_LENGTH, result.length)
        // Pattern should be: first_block + fillers + remaining_blocks
        assertTrue(result.startsWith("P<FRA<"))
        assertTrue(result.endsWith("TESTJOHN"))

        // All fillers should be between first block and remaining blocks
        val firstBlockEnd = 5
        val remainingBlocksStart = result.indexOf("TEST")
        assertTrue(remainingBlocksStart > firstBlockEnd)

        // Everything between should be fillers
        val betweenText = result.substring(firstBlockEnd, remainingBlocksStart)
        assertTrue(betweenText.all { it == '<' })
    }

    @Test
    fun `reconstruct does not pad TD1 ID card whose name line starts with P`() {
        val blocks = listOf(
            TextBlock("IDROUAB12345671<<<<<<<<<<<<<<<", Rect(0, 0, 300, 20)),
            TextBlock("9002155M3106305ROU<<<<<<<<<<<4", Rect(0, 30, 300, 50)),
            TextBlock("POPESCU<<ION<<<<<<<<<<<<<<<<<<", Rect(0, 60, 300, 80))
        )

        val result = MRZLineReconstructor.reconstruct(blocks)

        assertEquals(
            "IDROUAB12345671<<<<<<<<<<<<<<<\n" +
                    "9002155M3106305ROU<<<<<<<<<<<4\n" +
                    "POPESCU<<ION<<<<<<<<<<<<<<<<<<",
            result
        )
    }

    @Test
    fun `reconstruct does not pad TD2 ID card whose document number starts with P`() {
        val blocks = listOf(
            TextBlock("IDROUPOPESCU<<MARIA<<<<<<<<<<<<<<<<<", Rect(0, 0, 360, 20)),
            TextBlock("PH123456<7ROU8001014F300101912345672", Rect(0, 30, 360, 50))
        )

        val result = MRZLineReconstructor.reconstruct(blocks)

        assertEquals(
            "IDROUPOPESCU<<MARIA<<<<<<<<<<<<<<<<<\n" +
                    "PH123456<7ROU8001014F300101912345672",
            result
        )
    }

    @Test
    fun `reconstruct with zero-height blocks uses fallback grouping`() {
        val blocks = listOf(
            TextBlock("P<FRATEST", Rect(0, 10, 100, 10)),
            TextBlock("JOHN", Rect(200, 10, 250, 10))
        )

        val result = MRZLineReconstructor.reconstruct(blocks)

        // Should still work and group them together
        assertTrue(result.contains("P<FRATEST"))
        assertTrue(result.contains("JOHN"))
    }
}
