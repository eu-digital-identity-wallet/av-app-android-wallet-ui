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

package eu.europa.ec.commonfeature.countdown

import eu.europa.ec.businesslogic.provider.ElapsedRealtimeClock
import eu.europa.ec.testlogic.rule.CoroutineTestRule
import junit.framework.TestCase.assertEquals
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runTest
import org.junit.Rule
import org.junit.Test

class TestLockoutCountdownManager {

    @get:Rule
    val coroutineRule = CoroutineTestRule()

    private var fakeNow: Long = 0L
    private val clock: ElapsedRealtimeClock = ElapsedRealtimeClock { fakeNow }

    //region start — immediate expiry

    // Case 1:
    // Lockout end time is already in the past when start() is called.
    @Test
    fun `Given Case 1, When start is called and lockout has already expired, Then onLockoutEnd is fired immediately`() =
        coroutineRule.testScope.runTest {
            // Given
            fakeNow = 5_000L
            var lockoutEndFired = false

            val manager = LockoutCountdownManager(
                coroutineScope = this,
                clock = clock,
                getIsLockedOut = { true },
                getLockoutEndTime = { fakeNow - 1L },
                onCountdownUpdate = {},
                onLockoutEnd = { lockoutEndFired = true },
                getTimeMessage = { _, _ -> "" }
            )

            // When
            manager.start()
            advanceTimeBy(1)

            // Then
            assertEquals(true, lockoutEndFired)
        }

    //endregion

    //region start — countdown messages

    // Case 2:
    // A 3-second lockout produces countdown messages with the correct remaining time.
    @Test
    fun `Given Case 2, When start is called with a 3-second lockout, Then countdown messages decrease each second`() =
        coroutineRule.testScope.runTest {
            // Given
            fakeNow = 0L
            val lockoutEnd = 3_000L
            val messages = mutableListOf<String>()
            var lockoutEndFired = false
            var isLockedOut = true

            val manager = LockoutCountdownManager(
                coroutineScope = this,
                clock = clock,
                getIsLockedOut = { isLockedOut },
                getLockoutEndTime = { lockoutEnd },
                onCountdownUpdate = { msg -> msg?.let { messages.add(it) } },
                onLockoutEnd = { lockoutEndFired = true; isLockedOut = false },
                getTimeMessage = { minutes, seconds -> "${minutes}m${seconds}s" }
            )

            // When
            manager.start()

            // Tick t=0ms: first iteration, remaining = 3s
            advanceTimeBy(1)
            assertEquals("0m3s", messages.lastOrNull())

            // Tick t=1s: remaining = 2s
            fakeNow = 1_000L
            advanceTimeBy(1_000)
            assertEquals("0m2s", messages.lastOrNull())

            // Tick t=2s: remaining = 1s
            fakeNow = 2_000L
            advanceTimeBy(1_000)
            assertEquals("0m1s", messages.lastOrNull())

            // Tick t=3s: lockout expired
            fakeNow = 3_000L
            advanceTimeBy(1_000)
            assertEquals(true, lockoutEndFired)
        }

    //endregion

    //region cancel

    // Case 3:
    // cancel() stops the loop before any tick completes.
    @Test
    fun `Given Case 3, When cancel is called before the loop ticks, Then no updates are emitted`() =
        coroutineRule.testScope.runTest {
            // Given
            fakeNow = 0L
            val lockoutEnd = 60_000L
            var updateCount = 0

            val manager = LockoutCountdownManager(
                coroutineScope = this,
                clock = clock,
                getIsLockedOut = { true },
                getLockoutEndTime = { lockoutEnd },
                onCountdownUpdate = { updateCount++ },
                onLockoutEnd = {},
                getTimeMessage = { _, _ -> "" }
            )

            // When
            manager.start()
            manager.cancel()
            advanceTimeBy(5_000)

            // Then
            assertEquals(0, updateCount)
        }

    //endregion

    //region start — not locked out initially

    // Case 4:
    // getIsLockedOut returns false immediately — loop should not run.
    @Test
    fun `Given Case 4, When start is called but device is not locked out, Then no updates are emitted`() =
        coroutineRule.testScope.runTest {
            // Given
            var updateCount = 0

            val manager = LockoutCountdownManager(
                coroutineScope = this,
                clock = clock,
                getIsLockedOut = { false },
                getLockoutEndTime = { 0L },
                onCountdownUpdate = { updateCount++ },
                onLockoutEnd = {},
                getTimeMessage = { _, _ -> "" }
            )

            // When
            manager.start()
            advanceTimeBy(5_000)

            // Then
            assertEquals(0, updateCount)
        }

    //endregion
}
