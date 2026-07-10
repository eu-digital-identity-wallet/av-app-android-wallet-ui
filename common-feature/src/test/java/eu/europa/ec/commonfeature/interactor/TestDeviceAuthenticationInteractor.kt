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

package eu.europa.ec.commonfeature.interactor

import eu.europa.ec.authenticationlogic.controller.authentication.BiometricsAvailability
import eu.europa.ec.authenticationlogic.controller.authentication.DeviceAuthenticationController
import eu.europa.ec.authenticationlogic.controller.authentication.DeviceAuthenticationResult
import eu.europa.ec.authenticationlogic.model.BiometricCrypto
import eu.europa.ec.testfeature.util.mockedNotifyOnAuthenticationFailure
import eu.europa.ec.testlogic.base.TestApplication
import eu.europa.ec.testlogic.base.getMockedContext
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mock
import org.mockito.Mockito.mock
import org.mockito.Mockito.verify
import org.mockito.MockitoAnnotations
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(application = TestApplication::class, sdk = [36])
class TestDeviceAuthenticationInteractor {

    @Mock
    lateinit var deviceAuthenticationController: DeviceAuthenticationController

    @Mock
    private lateinit var resultHandler: DeviceAuthenticationResult

    private lateinit var interactor: DeviceAuthenticationInteractor

    private lateinit var closeable: AutoCloseable

    private lateinit var biometricCrypto: BiometricCrypto

    @Before
    fun before() {
        closeable = MockitoAnnotations.openMocks(this)
        interactor = DeviceAuthenticationInteractorImpl(
            deviceAuthenticationController = deviceAuthenticationController
        )

        biometricCrypto = BiometricCrypto(cryptoObject = null)
    }

    @After
    fun after() {
        closeable.close()
    }

    // Case: getBiometricsAvailability behaviour
    @Test
    fun `Given a BiometricsAvailability listener, When getBiometricsAvailability is called, Then deviceSupportsBiometrics should be triggered`() {
        // Given
        val mockListener: (BiometricsAvailability) -> Unit = mock()

        // When
        interactor.getBiometricsAvailability(
            listener = mockListener
        )

        // Then
        verify(deviceAuthenticationController).deviceSupportsBiometrics(mockListener)
    }

    // Case: authenticateWithBiometrics behaviour
    @Test
    fun `When authenticateWithBiometrics is called, Then authenticate function should be executed`() {
        // Given
        val context = getMockedContext()

        // When
        interactor.authenticateWithBiometrics(
            context = context,
            crypto = biometricCrypto,
            notifyOnAuthenticationFailure = mockedNotifyOnAuthenticationFailure,
            resultHandler = resultHandler
        )

        // Then
        verify(deviceAuthenticationController).authenticate(
            context = context,
            biometryCrypto = biometricCrypto,
            notifyOnAuthenticationFailure = mockedNotifyOnAuthenticationFailure,
            result = resultHandler
        )
    }
}
