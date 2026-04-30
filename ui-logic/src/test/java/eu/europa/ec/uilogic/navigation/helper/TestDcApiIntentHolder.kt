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

package eu.europa.ec.uilogic.navigation.helper

import android.content.Intent
import eu.europa.ec.businesslogic.provider.ElapsedRealtimeClock
import junit.framework.TestCase.assertEquals
import junit.framework.TestCase.assertNull
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.mockito.Mock
import org.mockito.MockitoAnnotations

class TestDcApiIntentHolder {

    @Mock
    private lateinit var intent: Intent

    private lateinit var closeable: AutoCloseable

    private var fakeNow: Long = 0L
    private val clock: ElapsedRealtimeClock = ElapsedRealtimeClock { fakeNow }

    private lateinit var holder: DcApiIntentHolder

    @Before
    fun before() {
        closeable = MockitoAnnotations.openMocks(this)
        fakeNow = 1_000_000L
        holder = DcApiIntentHolder(clock)
    }

    @After
    fun after() {
        closeable.close()
    }

    //region retrieveIntent — no cached intent

    // Case 1:
    // retrieveIntent() called with nothing cached returns null.
    @Test
    fun `Given Case 1, When retrieveIntent is called with no cached intent, Then it returns null`() {
        // When
        val result = holder.retrieveIntent()

        // Then
        assertNull(result)
    }
    //endregion

    //region retrieveIntent — fresh intent

    // Case 2:
    // Intent retrieved immediately after caching (age = 0) is returned.
    @Test
    fun `Given Case 2, When retrieveIntent is called immediately after caching, Then the intent is returned`() {
        // Given
        holder.cacheIntent(intent)

        // When
        val result = holder.retrieveIntent()

        // Then
        assertEquals(intent, result)
    }
    //endregion

    //region retrieveIntent — within TTL

    // Case 3:
    // Intent retrieved within the 60-second TTL is valid.
    @Test
    fun `Given Case 3, When retrieveIntent is called within the 60-second TTL, Then the intent is returned`() {
        // Given
        holder.cacheIntent(intent)
        fakeNow += 59_999L

        // When
        val result = holder.retrieveIntent()

        // Then
        assertEquals(intent, result)
    }
    //endregion

    //region retrieveIntent — expired TTL

    // Case 4:
    // Intent retrieved after 60 seconds (age > TTL) is discarded.
    @Test
    fun `Given Case 4, When retrieveIntent is called after the TTL expires, Then it returns null`() {
        // Given
        holder.cacheIntent(intent)
        fakeNow += 60_001L

        // When
        val result = holder.retrieveIntent()

        // Then
        assertNull(result)
    }

    // Case 5:
    // Intent retrieved exactly at the TTL boundary (age == 60 000) is still valid.
    @Test
    fun `Given Case 5, When retrieveIntent is called at the exact TTL boundary, Then the intent is returned`() {
        // Given
        holder.cacheIntent(intent)
        fakeNow += 60_000L

        // When
        val result = holder.retrieveIntent()

        // Then
        assertEquals(intent, result)
    }
    //endregion

    //region retrieveIntent — consume-once semantics

    // Case 6:
    // A second retrieve after the first returns null (intent is consumed).
    @Test
    fun `Given Case 6, When retrieveIntent is called twice, Then the second call returns null`() {
        // Given
        holder.cacheIntent(intent)
        holder.retrieveIntent()

        // When
        val secondResult = holder.retrieveIntent()

        // Then
        assertNull(secondResult)
    }
    //endregion

    //region cacheIntent — null clears the cache

    // Case 7:
    // Caching null replaces a previously cached intent.
    @Test
    fun `Given Case 7, When cacheIntent is called with null after a valid intent, Then retrieveIntent returns null`() {
        // Given
        holder.cacheIntent(intent)
        holder.cacheIntent(null)

        // When
        val result = holder.retrieveIntent()

        // Then
        assertNull(result)
    }

    //endregion
}
