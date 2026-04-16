/*
 * Copyright (c) 2023 European Commission
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

package eu.europa.ec.onboardingfeature.ui.passport.passportlivevideo

import android.content.Context
import androidx.lifecycle.viewModelScope
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.businesslogic.model.ErrorType
import eu.europa.ec.onboardingfeature.config.PassportLiveVideoUiConfig
import eu.europa.ec.onboardingfeature.interactor.FaceMatchPartialState
import eu.europa.ec.onboardingfeature.interactor.FaceMatchSDKPartialState
import eu.europa.ec.onboardingfeature.interactor.PassportLiveVideoInteractor
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.uilogic.component.content.ContentErrorConfig
import eu.europa.ec.uilogic.extension.createErrorConfigFromMessage
import eu.europa.ec.uilogic.mvi.MviViewModel
import eu.europa.ec.uilogic.mvi.ViewEvent
import eu.europa.ec.uilogic.mvi.ViewSideEffect
import eu.europa.ec.uilogic.mvi.ViewState
import eu.europa.ec.uilogic.navigation.OnboardingScreens
import eu.europa.ec.uilogic.serializer.UiSerializer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.koin.android.annotation.KoinViewModel
import org.koin.core.annotation.InjectedParam
import java.io.File

private const val TAG = "PassportLiveVideoViewModel"

data class State(
    val isLoading: Boolean = false,
    val config: PassportLiveVideoUiConfig? = null,
    val progress: Int = 0, // 0-100 percentage for initialization
    val isInitializing: Boolean = false,
    val isSdkReady: Boolean = false,
    val error: ContentErrorConfig? = null,
) : ViewState

sealed class Event : ViewEvent {
    data object OnBackPressed : Event()
    data object OnLiveVideoCapture : Event()
    data object OnRetry : Event()
    data class InitializeSdk(val context: Context) : Event()
}

sealed class Effect : ViewSideEffect {
    sealed class Navigation : Effect() {
        data object GoBack : Navigation()
        data class SwitchScreen(val screenRoute: String, val inclusive: Boolean) : Navigation()
    }

    data class Failure(val message: String) : Effect()
    data class CaptureSuccess(val message: String) : Effect()
}

@KoinViewModel
class PassportLiveVideoViewModel(
    private val uiSerializer: UiSerializer,
    private val logController: LogController,
    private val passportLiveVideoInteractor: PassportLiveVideoInteractor,
    private val resourceProvider: ResourceProvider,
    @InjectedParam private val passportLiveVideoSerializedConfig: String,
) : MviViewModel<Event, State, Effect>() {

    override fun setInitialState(): State {
        logController.d(TAG) { "get the following param=$passportLiveVideoSerializedConfig" }
        val config: PassportLiveVideoUiConfig? = uiSerializer.fromBase64(
            passportLiveVideoSerializedConfig,
            PassportLiveVideoUiConfig::class.java,
            PassportLiveVideoUiConfig.Parser
        )
        return State(config = config)
    }

    override fun handleEvents(event: Event) {
        when (event) {
            Event.OnBackPressed -> {
                viewState.value.config?.faceImageTempPath?.let { deleteTempFile(it) }
                setEffect { Effect.Navigation.GoBack }
            }

            Event.OnLiveVideoCapture -> {
                logController.d(tag = TAG) { "Event invoked OnLiveVideoCapture" }
                handleLiveVideoCapture()
            }

            is Event.InitializeSdk -> {
                initializeSdk(event.context)
            }

            Event.OnRetry -> {
                logController.d(tag = TAG) { "Event invoked OnRetry" }
                setState { copy(error = null) }
            }
        }
    }

    private fun initializeSdk(context: Context) {
        setState { copy(error = null) }

        viewModelScope.launch {
            passportLiveVideoInteractor.initFaceMatchSDK(context).collectLatest { initState ->
                withContext(Dispatchers.Main) {
                    when (initState) {
                        is FaceMatchSDKPartialState.NotInitialized -> {
                            logController.d(TAG) { "SDK not initialized" }
                            setState { copy(isInitializing = false, progress = 0) }
                        }

                        is FaceMatchSDKPartialState.Preparing -> {
                            logController.d(TAG) { "Preparing models: ${initState.progress}%" }
                            setState { copy(isInitializing = true, progress = initState.progress) }
                        }

                        is FaceMatchSDKPartialState.Initializing -> {
                            logController.d(TAG) { "Initializing SDK" }
                            setState { copy(isInitializing = true, progress = 100) }
                        }

                        is FaceMatchSDKPartialState.Ready -> {
                            logController.i(TAG) { "SDK ready" }
                            setState {
                                copy(
                                    isInitializing = false,
                                    isSdkReady = true,
                                    progress = 100
                                )
                            }
                        }

                        is FaceMatchSDKPartialState.Error -> {
                            logController.e(TAG) { "SDK initialization error: ${initState.message}" }
                            setState { copy(isInitializing = false, progress = 0) }
                            showError(initState.message, initState.errorType)
                        }
                    }
                }
            }
        }
    }

    private fun handleLiveVideoCapture() {
        val config = viewState.value.config
        if (config == null) {
            logController.e(TAG) { "Config is null, cannot proceed with live video capture" }
            showError(resourceProvider.getString(R.string.generic_error_retry))
            return
        }

        setState { copy(isLoading = true, error = null) }

        viewModelScope.launch {
            try {
                when (val matchResult = passportLiveVideoInteractor.captureAndMatchFace(
                    faceImageTempPath = config.faceImageTempPath
                )) {
                    is FaceMatchPartialState.Success -> {
                        logController.i(TAG) { "Face match successful, navigating to consent screen" }
                        setState { copy(isLoading = false) }
                        deleteTempFile(config.faceImageTempPath)
                        navigateToNextScreen()
                    }

                    is FaceMatchPartialState.Failure -> {
                        logController.e(TAG) { "Face match failed: ${matchResult.error}" }
                        setState { copy(isLoading = false) }
                        deleteTempFile(config.faceImageTempPath)
                        showError(matchResult.error)
                    }
                }
            } catch (e: Exception) {
                logController.e(TAG, e) { "Exception during live video capture" }
                setState { copy(isLoading = false) }
                deleteTempFile(config.faceImageTempPath)
                showError(e.message ?: "An unexpected error occurred")
            }
        }
    }

    private fun navigateToNextScreen() {
        setEffect {
            Effect.Navigation.SwitchScreen(
                screenRoute = OnboardingScreens.IdentityDocumentCredentialIssuance.screenRoute,
                inclusive = false
            )
        }
    }


    private fun deleteTempFile(filePath: String) {
        try {
            val file = File(filePath)
            if (file.exists()) {
                file.delete()
            }
        } catch (e: Exception) {
            logController.e(TAG, e) { "Exception while deleting temp file" }
        }
    }


    private fun showError(errorMessage: String, errorType: ErrorType = ErrorType.GENERIC) {
        setState {
            copy(
                error = createErrorConfigFromMessage(
                    errorMessage = errorMessage,
                    resourceProvider = resourceProvider,
                    errorType = errorType,
                    onCancel = { setEvent(Event.OnBackPressed) },
                    onRetry = { setEvent(Event.OnRetry) },
                )
            )
        }
    }

}
