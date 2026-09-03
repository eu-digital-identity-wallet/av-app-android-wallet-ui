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

package eu.europa.ec.onboardingfeature.ui.passport.passportscanintro

import android.content.Context
import androidx.lifecycle.viewModelScope
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.onboardingfeature.interactor.PassportScanIntroInteractor
import eu.europa.ec.passportscanner.face.SdkInitStatus
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.provider.ResourceProvider
import eu.europa.ec.uilogic.component.content.ContentErrorConfig
import eu.europa.ec.uilogic.extension.createErrorConfigFromMessage
import eu.europa.ec.uilogic.mvi.MviViewModel
import eu.europa.ec.uilogic.mvi.ViewEvent
import eu.europa.ec.uilogic.mvi.ViewSideEffect
import eu.europa.ec.uilogic.mvi.ViewState
import eu.europa.ec.uilogic.navigation.OnboardingScreens
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import org.koin.android.annotation.KoinViewModel

private const val TAG = "PassportScanIntroViewModel"

enum class SdkReadiness { NotReady, Downloading, Ready }

data class State(
    val isLoading: Boolean = false,
    val sdkReadiness: SdkReadiness = SdkReadiness.NotReady,
    val downloadProgress: Int = 0,
    val downloadStatusAnnouncement: String = "",
    val error: ContentErrorConfig? = null,
) : ViewState

sealed class Event : ViewEvent {
    data object OnBackPressed : Event()
    data class OnDownloadClicked(val context: Context) : Event()
    data object OnStartClicked : Event()
    data class OnRetryClicked(val context: Context) : Event()
}

sealed class Effect : ViewSideEffect {
    sealed class Navigation : Effect() {
        data object GoBack : Navigation()
        data class SwitchScreen(val screenRoute: String, val inclusive: Boolean) : Navigation()
    }

    data object FocusStartButton : Effect()
}

@KoinViewModel
class PassportScanIntroViewModel(
    private val logController: LogController,
    private val passportScanIntroInteractor: PassportScanIntroInteractor,
    private val resourceProvider: ResourceProvider,
) : MviViewModel<Event, State, Effect>() {

    private var downloadJob: Job? = null

    override fun setInitialState(): State = State()

    override fun handleEvents(event: Event) {
        when (event) {
            is Event.OnBackPressed -> {
                downloadJob?.cancel()
                passportScanIntroInteractor.cancelFaceMatchSDKInit()
                setEffect { Effect.Navigation.GoBack }
            }

            is Event.OnDownloadClicked -> startDownload(event.context)

            is Event.OnRetryClicked -> startDownload(event.context)

            is Event.OnStartClicked -> {
                setEffect {
                    Effect.Navigation.SwitchScreen(
                        OnboardingScreens.DocumentIdentification.screenRoute,
                        inclusive = false
                    )
                }
            }
        }
    }

    private fun startDownload(context: Context) {
        setState {
            copy(
                sdkReadiness = SdkReadiness.Downloading,
                downloadStatusAnnouncement = "",
                error = null
            )
        }
        collectSdkInit(context.applicationContext)
    }

    private fun collectSdkInit(context: Context) {
        downloadJob?.cancel()
        downloadJob = viewModelScope.launch {
            passportScanIntroInteractor.initFaceMatchSDK(context).collect { status ->
                logController.d(TAG) { "SDK init status: $status" }
                when (status) {
                    is SdkInitStatus.NotInitialized -> {
                        // Keep current state — SDK not yet started
                    }

                    is SdkInitStatus.Preparing -> {
                        setState {
                            copy(
                                sdkReadiness = SdkReadiness.Downloading,
                                downloadProgress = status.progress,
                                downloadStatusAnnouncement = progressAnnouncement(status.progress),
                                error = null
                            )
                        }
                    }

                    is SdkInitStatus.Initializing -> {
                        setState {
                            copy(
                                sdkReadiness = SdkReadiness.Downloading,
                                downloadProgress = 100,
                                downloadStatusAnnouncement = resourceProvider.getString(
                                    R.string.passport_scan_intro_download_preparing_announcement
                                ),
                                error = null
                            )
                        }
                    }

                    is SdkInitStatus.Ready -> {
                        setState {
                            copy(
                                sdkReadiness = SdkReadiness.Ready,
                                downloadProgress = 100,
                                error = null
                            )
                        }
                        setEffect { Effect.FocusStartButton }
                    }

                    is SdkInitStatus.Error -> {
                        setState {
                            copy(
                                sdkReadiness = SdkReadiness.NotReady,
                                downloadProgress = 0,
                                downloadStatusAnnouncement = "",
                                error = createErrorConfigFromMessage(
                                    errorMessage = status.message,
                                    resourceProvider = resourceProvider,
                                    errorType = status.errorType,
                                    onRetry = {
                                        setEvent(Event.OnRetryClicked(context))
                                    },
                                    onCancel = {
                                        setState {
                                            copy(error = null)
                                        }
                                    }
                                )
                            )
                        }
                    }
                }
            }
        }
    }

    private fun progressAnnouncement(progress: Int): String {
        val announcedProgress = progress - progress % PROGRESS_ANNOUNCEMENT_STEP
        return if (announcedProgress == 0) {
            ""
        } else {
            resourceProvider.getString(
                R.string.passport_scan_intro_download_progress_announcement,
                announcedProgress
            )
        }
    }

    private companion object {
        const val PROGRESS_ANNOUNCEMENT_STEP = 25
    }
}
