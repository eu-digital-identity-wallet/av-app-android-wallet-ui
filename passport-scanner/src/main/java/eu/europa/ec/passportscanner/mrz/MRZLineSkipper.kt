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

import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.passportscanner.parser.MrzRecord

/**
 * Utility class to try different combinations of MRZ lines when multiple lines are detected.
 * This helps handle cases where OCR detects extra lines that aren't part of the actual MRZ.
 */
class MRZLineSkipper(
    val logController: LogController,
    private val parseCallback: (String, LogController) -> MrzRecord
) {

    companion object {
        private const val TAG = "MRZLineSkipper"
    }

    /**
     * Try to parse MRZ by attempting different line combinations.
     * When 3+ lines are detected, tries windows of 2 and 3 lines.
     *
     * @param cleanedMrz The cleaned MRZ string from MRZCleaner
     * @return Valid MrzRecord if found, null otherwise
     */
    fun tryParse(cleanedMrz: String): MrzRecord? {
        val lines = cleanedMrz.split('\n').filter { it.isNotEmpty() }

        if (lines.size < 3) {
            return tryParseLines(lines)
        }

        // Try window of 3 lines - TD1 format
        checkWindow(3, lines, isPassportCheck = false)?.let { return it }

        // Try window of 2 lines - TD3/Passport format
        checkWindow(2, lines, isPassportCheck = true)?.let { return it }

        return null
    }

    /**
     * Try different windows of lines, keeping order.
     * For numLines=2, lines=[1,2,3]: tries [1,2], [1,3], [2,3]
     * For numLines=3, lines=[1,2,3,4]: tries [1,2,3], [1,2,4], [1,3,4], [2,3,4]
     *
     * @param numLines Number of lines in each window (2 or 3)
     * @param linesArray Array of all detected lines
     * @param isPassportCheck True for TD3 passport validation (first line starts with 'P', second ends with digit)
     * @return Valid MrzRecord if found, null otherwise
     */
    private fun checkWindow(
        numLines: Int,
        linesArray: List<String>,
        isPassportCheck: Boolean
    ): MrzRecord? {
        if (numLines > linesArray.size) {
            return null
        }

        // Generate all combinations of indices
        val combinations = generateCombinations(linesArray.size, numLines)

        for ((index, combo) in combinations.withIndex()) {
            val selectedLines = combo.map { linesArray[it] }

            if (isPassportCheck) {
                if (!checkPassportRequirements(selectedLines)) {
                    continue
                }
            }

            tryParseLines(selectedLines)?.let { record ->
                return record
            }
        }

        return null
    }

    private fun checkPassportRequirements(selectedLines: List<String>): Boolean {
        val firstLine = selectedLines.firstOrNull()

        // First line must start with 'P'
        if (firstLine.isNullOrEmpty() || !firstLine.startsWith("P")) {
            return false
        }

        val secondLine = if (selectedLines.size >= 2) selectedLines[1] else null
        // Second line must end with digit
        if (secondLine.isNullOrEmpty() || !secondLine.last().isDigit()) {
            return false
        }
        return true
    }

    /**
     * Generate all combinations of k elements from n elements (C(n,k))
     * Returns list of index combinations, preserving order.
     *
     * Example: generateCombinations(3, 2) returns [[0,1], [0,2], [1,2]]
     * Example: generateCombinations(4, 3) returns [[0,1,2], [0,1,3], [0,2,3], [1,2,3]]
     */
    private fun generateCombinations(n: Int, k: Int): List<List<Int>> {
        if (k > n || k <= 0) return emptyList()
        if (k == n) return listOf((0 until n).toList())

        val result = mutableListOf<List<Int>>()
        val combination = IntArray(k)

        fun backtrack(start: Int, depth: Int) {
            if (depth == k) {
                result.add(combination.toList())
                return
            }

            for (i in start until n) {
                combination[depth] = i
                backtrack(i + 1, depth + 1)
            }
        }

        backtrack(0, 0)
        return result
    }

    /**
     * Attempt to parse a list of lines as an MRZ record.
     *
     * @param lines Lines to combine and parse
     * @return Valid MrzRecord if successful, null otherwise
     */
    private fun tryParseLines(lines: List<String>): MrzRecord? {
        if (lines.isEmpty()) return null

        val mrzString = lines.joinToString("\n")

        return try {
            val record = parseCallback(mrzString, logController)

            // Check if the record has valid checksums
            if (record.validDateOfBirth &&
                record.validDocumentNumber &&
                record.validExpirationDate ||
                record.validComposite) {
                record
            } else {
                null
            }
        } catch (e: Exception) {
            logController.d(TAG) { "Parse failed (${e.javaClass.simpleName})" }
            null
        }
    }
}
