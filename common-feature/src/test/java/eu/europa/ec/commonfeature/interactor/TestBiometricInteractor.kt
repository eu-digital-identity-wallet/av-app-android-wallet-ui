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

package eu.europa.ec.commonfeature.interactor

import android.content.Context
import androidx.fragment.app.FragmentActivity
import eu.europa.ec.authenticationlogic.controller.authentication.BiometricAuthenticationController
import eu.europa.ec.authenticationlogic.controller.authentication.BiometricPromptData
import eu.europa.ec.authenticationlogic.controller.authentication.BiometricVaultResult
import eu.europa.ec.authenticationlogic.controller.authentication.BiometricsAvailability
import eu.europa.ec.authenticationlogic.controller.storage.BiometryStorageController
import eu.europa.ec.authenticationlogic.storage.BiometricKeyInvalidatedException
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.testlogic.base.TestApplication
import eu.europa.ec.testlogic.extension.runFlowTest
import eu.europa.ec.testlogic.extension.runTest
import eu.europa.ec.testlogic.extension.toFlow
import eu.europa.ec.testlogic.rule.CoroutineTestRule
import junit.framework.TestCase.assertEquals
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mock
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.whenever
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import javax.crypto.Cipher

@RunWith(RobolectricTestRunner::class)
@Config(application = TestApplication::class)
class TestBiometricInteractor {

    @get:Rule
    val coroutineRule = CoroutineTestRule()

    @Mock
    private lateinit var biometryStorageController: BiometryStorageController

    @Mock
    private lateinit var biometricAuthenticationController: BiometricAuthenticationController

    @Mock
    private lateinit var resourceProvider: ResourceProvider

    @Mock
    private lateinit var quickPinInteractor: QuickPinInteractor

    @Mock
    private lateinit var cipher: Cipher

    @Mock
    private lateinit var fragmentActivity: FragmentActivity

    private lateinit var interactor: BiometricInteractor

    private lateinit var closeable: AutoCloseable

    @Before
    fun before() {
        closeable = MockitoAnnotations.openMocks(this)
        whenever(resourceProvider.getString(org.mockito.kotlin.any())).thenReturn("mock")

        interactor = BiometricInteractorImpl(
            biometryStorageController = biometryStorageController,
            biometricAuthenticationController = biometricAuthenticationController,
            resourceProvider = resourceProvider,
            quickPinInteractor = quickPinInteractor
        )
    }

    @After
    fun after() {
        closeable.close()
    }

    @Test
    fun `Given isCurrentPinValid returns state Success, When isPinValid is called, Then assert the result is the expected`() =
        coroutineRule.runTest {
            whenever(quickPinInteractor.isCurrentPinValid(mockedPin)).thenReturn(
                QuickPinInteractorPinValidPartialState.Success.toFlow()
            )

            interactor.isPinValid(mockedPin).runFlowTest {
                val expectedResult = QuickPinInteractorPinValidPartialState.Success
                assertEquals(expectedResult, awaitItem())
            }
        }

    @Test
    fun `When launchBiometricSystemScreen is called, Then verify function is executed on the controller`() {
        interactor.launchBiometricSystemScreen()

        org.mockito.kotlin.verify(biometricAuthenticationController).launchBiometricSystemScreen()
    }

    @Test
    fun `When getBiometricUserSelection is called, Then assert the correct value is returned`() {
        whenever(biometryStorageController.getUseBiometricsAuth()).thenReturn(true)

        val result = interactor.getBiometricUserSelection()

        assertEquals(true, result)
        org.mockito.kotlin.verify(biometryStorageController).getUseBiometricsAuth()
    }

    @Test
    fun `When storeBiometricsUsageDecision is called, Then verify setUseBiometricsAuth is executed`() {
        val shouldUseBiometrics = true

        interactor.storeBiometricsUsageDecision(shouldUseBiometrics = shouldUseBiometrics)

        org.mockito.kotlin.verify(biometryStorageController).setUseBiometricsAuth(shouldUseBiometrics)
    }

    @Test
    fun `When getBiometricsAvailability is called, Then verify deviceSupportsBiometrics is executed`() {
        val mockListener: (BiometricsAvailability) -> Unit = org.mockito.kotlin.mock()

        interactor.getBiometricsAvailability(mockListener)

        org.mockito.kotlin.verify(biometricAuthenticationController).deviceSupportsBiometrics(mockListener)
    }

    @Test
    fun `Given enrollBiometric returns cipher and auth succeeds, When enrollBiometricVault, Then returns Success`() =
        coroutineRule.runTest {
            whenever(biometryStorageController.enrollBiometric()).thenReturn(cipher)
            whenever(biometricAuthenticationController.authenticate(
                org.mockito.kotlin.any(),
                org.mockito.kotlin.any(),
                org.mockito.kotlin.any(),
                org.mockito.kotlin.any()
            )).thenReturn(BiometricPromptData(org.mockito.kotlin.mock()))
            whenever(biometryStorageController.commitBiometricEnrolment(org.mockito.kotlin.any())).thenReturn(Unit)

            val result = interactor.enrollBiometricVault(fragmentActivity)

            assertEquals(BiometricVaultResult.Success, result)
        }

    @Test
    fun `Given enrollBiometric throws, When enrollBiometricVault, Then returns Failed`() =
        coroutineRule.runTest {
            whenever(biometryStorageController.enrollBiometric()).thenThrow(RuntimeException("keystore error"))

            val result = interactor.enrollBiometricVault(fragmentActivity)

            assertEquals(BiometricVaultResult.Failed::class, result::class)
        }

    @Test
    fun `Given non-Activity context, When enrollBiometricVault, Then returns Failed`() =
        coroutineRule.runTest {
            val nonActivityContext: Context = org.mockito.kotlin.mock()

            val result = interactor.enrollBiometricVault(nonActivityContext)

            assertEquals(BiometricVaultResult.Failed::class, result::class)
        }

    @Test
    fun `Given auth is cancelled, When enrollBiometricVault, Then returns Cancelled`() =
        coroutineRule.runTest {
            whenever(biometryStorageController.enrollBiometric()).thenReturn(cipher)
            whenever(biometricAuthenticationController.authenticate(
                org.mockito.kotlin.any(),
                org.mockito.kotlin.any(),
                org.mockito.kotlin.any(),
                org.mockito.kotlin.any()
            )).thenReturn(BiometricPromptData(null, 10, "cancelled"))

            val result = interactor.enrollBiometricVault(fragmentActivity)

            assertEquals(BiometricVaultResult.Cancelled, result)
        }

    @Test
    fun `Given commitBiometricEnrolment throws, When enrollBiometricVault, Then returns Failed`() =
        coroutineRule.runTest {
            whenever(biometryStorageController.enrollBiometric()).thenReturn(cipher)
            whenever(biometricAuthenticationController.authenticate(
                org.mockito.kotlin.any(),
                org.mockito.kotlin.any(),
                org.mockito.kotlin.any(),
                org.mockito.kotlin.any()
            )).thenReturn(BiometricPromptData(org.mockito.kotlin.mock()))
            whenever(biometryStorageController.commitBiometricEnrolment(org.mockito.kotlin.any())).thenThrow(
                RuntimeException("write failed")
            )

            val result = interactor.enrollBiometricVault(fragmentActivity)

            assertEquals(BiometricVaultResult.Failed::class, result::class)
        }

    @Test
    fun `Given prepareBiometricUnlock returns cipher and auth succeeds, When unlockWithBiometrics, Then returns Success`() =
        coroutineRule.runTest {
            whenever(biometryStorageController.prepareBiometricUnlock()).thenReturn(cipher)
            whenever(biometricAuthenticationController.authenticate(
                org.mockito.kotlin.any(),
                org.mockito.kotlin.any(),
                org.mockito.kotlin.any(),
                org.mockito.kotlin.any()
            )).thenReturn(BiometricPromptData(org.mockito.kotlin.mock()))
            whenever(biometryStorageController.completeBiometricUnlock(org.mockito.kotlin.any())).thenReturn(Unit)

            val result = interactor.unlockWithBiometrics(fragmentActivity)

            assertEquals(BiometricVaultResult.Success, result)
        }

    @Test
    fun `Given prepareBiometricUnlock throws BiometricKeyInvalidatedException, When unlockWithBiometrics, Then returns KeyInvalidated`() =
        coroutineRule.runTest {
            whenever(biometryStorageController.prepareBiometricUnlock()).thenThrow(
                BiometricKeyInvalidatedException()
            )

            val result = interactor.unlockWithBiometrics(fragmentActivity)

            assertEquals(BiometricVaultResult.KeyInvalidated, result)
        }

    @Test
    fun `Given non-Activity context, When unlockWithBiometrics, Then returns Failed`() =
        coroutineRule.runTest {
            val nonActivityContext: Context = org.mockito.kotlin.mock()

            val result = interactor.unlockWithBiometrics(nonActivityContext)

            assertEquals(BiometricVaultResult.Failed::class, result::class)
        }

    @Test
    fun `Given auth is cancelled, When unlockWithBiometrics, Then returns Cancelled`() =
        coroutineRule.runTest {
            whenever(biometryStorageController.prepareBiometricUnlock()).thenReturn(cipher)
            whenever(biometricAuthenticationController.authenticate(
                org.mockito.kotlin.any(),
                org.mockito.kotlin.any(),
                org.mockito.kotlin.any(),
                org.mockito.kotlin.any()
            )).thenReturn(BiometricPromptData(null, 13, "cancelled"))

            val result = interactor.unlockWithBiometrics(fragmentActivity)

            assertEquals(BiometricVaultResult.Cancelled, result)
        }

    @Test
    fun `Given completeBiometricUnlock throws, When unlockWithBiometrics, Then returns Failed`() =
        coroutineRule.runTest {
            whenever(biometryStorageController.prepareBiometricUnlock()).thenReturn(cipher)
            whenever(biometricAuthenticationController.authenticate(
                org.mockito.kotlin.any(),
                org.mockito.kotlin.any(),
                org.mockito.kotlin.any(),
                org.mockito.kotlin.any()
            )).thenReturn(BiometricPromptData(org.mockito.kotlin.mock()))
            whenever(biometryStorageController.completeBiometricUnlock(org.mockito.kotlin.any())).thenThrow(
                RuntimeException("unlock failed")
            )

            val result = interactor.unlockWithBiometrics(fragmentActivity)

            assertEquals(BiometricVaultResult.Failed::class, result::class)
        }

    private val mockedPin = "1234"
}
