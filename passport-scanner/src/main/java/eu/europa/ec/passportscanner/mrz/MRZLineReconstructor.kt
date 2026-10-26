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
import kotlin.math.abs

/**
 * Utility to reconstruct MRZ lines from OCR text blocks that may be split horizontally.
 *
 * Common OCR issue: TD3 passports often get detected as 4 blocks (top-left, top-right,
 * bottom-left, bottom-right) instead of 2 lines, with "<" filler characters missed between blocks.
 */
object MRZLineReconstructor {

    private const val TD3_LINE_LENGTH = 44
    private const val MRZ_FILLER_CHAR = '<'

    /**
     * Represents a text block with its position
     */
    data class TextBlock(
        val text: String,
        val boundingBox: Rect
    )

    /**
     * Reconstructs MRZ text from blocks by grouping them into lines and filling gaps.
     *
     * @param blocks List of text blocks with bounding boxes from OCR
     * @return Reconstructed MRZ text with proper line breaks
     */
    fun reconstruct(blocks: List<TextBlock>): String {
        if (blocks.isEmpty()) {
            return ""
        }

        val lines = groupBlocksIntoLines(blocks)

        // The first line of a TD3 passport MRZ starts with 'P' and is followed by a second line.
        // The last line can start with 'P' on other documents too: the name line of a TD1 ID card
        // (e.g. "POPESCU<<ION") or the document number line of a TD2 card (e.g. "PH123456<"),
        // so it only counts when it is the only line read so far.
        val isTd3Passport = lines.withIndex().any { (index, lineBlocks) ->
            (index < lines.lastIndex || lines.size == 1) &&
                    lineBlocks.firstOrNull()?.text?.startsWith("P") == true
        }

        val reconstructedLines = lines.map { lineBlocks ->
            reconstructLine(lineBlocks, isTd3Passport)
        }

        return reconstructedLines.joinToString("\n")
    }

    /**
     * Groups text blocks into lines based on their vertical position (Y-coordinate).
     * Blocks are considered on the same line if their Y-centers are within a threshold.
     */
    private fun groupBlocksIntoLines(
        blocks: List<TextBlock>
    ): List<List<TextBlock>> {
        if (blocks.isEmpty()) return emptyList()

        // Calculate vertical center for each block
        val blocksWithCenter = blocks.map { block ->
            val centerY = (block.boundingBox.top + block.boundingBox.bottom) / 2
            block to centerY
        }

        // Sort by vertical position (top to bottom)
        val sortedBlocks = blocksWithCenter.sortedBy { it.second }

        // Group blocks with similar Y positions
        val lines = mutableListOf<MutableList<TextBlock>>()
        var currentLine = mutableListOf<TextBlock>()
        var currentCenterY = sortedBlocks.first().second

        // Threshold: blocks within 30% of average block height are considered same line
        val avgBlockHeight = blocks.map { it.boundingBox.height() }.average()
        val threshold = (avgBlockHeight * 0.3).toInt()

        for ((block, centerY) in sortedBlocks) {
            if (abs(centerY - currentCenterY) <= threshold) {
                // Same line
                currentLine.add(block)
            } else {
                // New line
                if (currentLine.isNotEmpty()) {
                    lines.add(currentLine)
                }
                currentLine = mutableListOf(block)
                currentCenterY = centerY
            }
        }

        // Add last line
        if (currentLine.isNotEmpty()) {
            lines.add(currentLine)
        }

        // Sort blocks within each line by X position (left to right)
        lines.forEach { line ->
            line.sortBy { it.boundingBox.left }
        }

        return lines
    }

    private fun reconstructLine(
        lineBlocks: List<TextBlock>,
        isTd3Passport: Boolean
    ): String {
        if (lineBlocks.isEmpty()) return ""

        if (lineBlocks.size == 1) {
            return handleSingleBlock(lineBlocks.first().text, isTd3Passport)
        }

        if (!isTd3Passport) {
            return lineBlocks.joinToString("") { it.text }
        }

        return buildTd3LineWithFillers(lineBlocks)
    }

    private fun handleSingleBlock(text: String, isTd3Passport: Boolean): String {
        return if (isTd3Passport && text.length < TD3_LINE_LENGTH) {
            padToTd3Length(text)
        } else {
            text
        }
    }

    private fun padToTd3Length(text: String): String {
        val paddingNeeded = TD3_LINE_LENGTH - text.length
        return text + MRZ_FILLER_CHAR.toString().repeat(paddingNeeded)
    }

    private fun buildTd3LineWithFillers(lineBlocks: List<TextBlock>): String {
        val currentTextLength = lineBlocks.sumOf { it.text.length }

        if (currentTextLength >= TD3_LINE_LENGTH) {
            return lineBlocks.joinToString("") { it.text }
        }

        val totalFillersNeeded = TD3_LINE_LENGTH - currentTextLength
        return buildString {
            lineBlocks.forEachIndexed { index, block ->
                append(block.text)
                if (index == 0 && lineBlocks.size > 1) {
                    append(MRZ_FILLER_CHAR.toString().repeat(totalFillersNeeded))
                }
            }
        }
    }
}
