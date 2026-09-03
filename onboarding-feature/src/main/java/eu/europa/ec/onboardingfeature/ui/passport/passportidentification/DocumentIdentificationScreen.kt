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

package eu.europa.ec.onboardingfeature.ui.passport.passportidentification

import android.app.Activity
import android.content.Context
import android.content.Intent
import androidx.activity.compose.ManagedActivityResultLauncher
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.ActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.painter.BitmapPainter
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.onboardingfeature.ui.passport.passportidentification.Effect.Navigation
import eu.europa.ec.onboardingfeature.ui.passport.passportidentification.Event.OnDocumentScanSuccessful
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.resourceslogic.theme.values.elevated
import eu.europa.ec.uilogic.component.AppIcons
import eu.europa.ec.uilogic.component.BulletHolder
import eu.europa.ec.uilogic.component.content.ContentScreen
import eu.europa.ec.uilogic.component.content.ScreenNavigateAction
import eu.europa.ec.uilogic.component.preview.PreviewTheme
import eu.europa.ec.uilogic.component.preview.ThemeModePreviews
import eu.europa.ec.uilogic.component.utils.SPACING_EXTRA_SMALL
import eu.europa.ec.uilogic.component.utils.SPACING_LARGE
import eu.europa.ec.uilogic.component.utils.SPACING_SMALL
import eu.europa.ec.uilogic.component.utils.VSpacer
import eu.europa.ec.uilogic.component.wrap.ButtonConfig
import eu.europa.ec.uilogic.component.wrap.ButtonType
import eu.europa.ec.uilogic.component.wrap.StickyBottomConfig
import eu.europa.ec.uilogic.component.wrap.StickyBottomType
import eu.europa.ec.uilogic.component.wrap.TextConfig
import eu.europa.ec.uilogic.component.wrap.WrapImage
import eu.europa.ec.uilogic.component.wrap.WrapStickyBottomContent
import eu.europa.ec.uilogic.component.wrap.WrapText
import org.koin.compose.koinInject
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Locale

@Composable
fun DocumentIdentificationScreen(
    controller: NavController,
    viewModel: DocumentIdentificationViewModel
) {

    val state by viewModel.viewState.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val logController = koinInject<LogController>()

    val mrzScannerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        when (result.resultCode) {
            Activity.RESULT_OK -> {
                result.data?.let { intent ->

                    val scannedDocument =
                        DocumentScannerIntentHelper.extractScannedDocumentFromIntent(
                            intent,
                            logController
                        )
                    if (scannedDocument.dateOfBirth == null && scannedDocument.expiryDate == null) {
                        viewModel.setEvent(Event.OnDocumentScanFailed(DocumentErrors.NoDocumentDataReceived))
                    } else {
                        viewModel.setEvent(OnDocumentScanSuccessful(scannedDocument))
                    }
                }
            }

            Activity.RESULT_CANCELED -> {
                viewModel.setEvent(Event.OnDocumentScanFailed(DocumentErrors.ScanCancelled))
            }

            else -> {
                viewModel.setEvent(Event.OnDocumentScanFailed(DocumentErrors.UnknownError))
            }
        }
    }

    ContentScreen(
        isLoading = state.isLoading,
        navigatableAction = ScreenNavigateAction.NONE,
        onBack = { viewModel.setEvent(Event.OnBackPressed) },
        contentErrorConfig = state.error,
        stickyBottom = { paddingValues ->
            ActionButtons(
                state = state,
                onBack = { viewModel.setEvent(Event.OnBackPressed) },
                onCapture = { viewModel.setEvent(Event.OnStartPassportScan) },
                onTryAgain = { viewModel.setEvent(Event.OnProcessRestartRequest) },
                onNext = { viewModel.setEvent(Event.OnPassportVerificationCompletion) },
                paddings = paddingValues
            )
        }
    ) { paddingValues ->
        if (state.scanComplete) {
            VerifyYourDataContent(
                scannedDocument = state.scannedDocument!!,
                paddingValues = paddingValues
            )
        } else {
            Content(paddingValues = paddingValues)
        }
    }

    LaunchedEffect(Unit) {
        viewModel.effect.collect { effect ->
            handleEffect(effect, controller, context, mrzScannerLauncher)
        }
    }

}

@Composable
private fun ActionButtons(
    state: State,
    onNext: () -> Unit = {},
    onBack: () -> Unit = {},
    onCapture: () -> Unit = {},
    onTryAgain: () -> Unit = {},
    paddings: PaddingValues,
) {

    val buttons = StickyBottomType.TwoButtons(
        primaryButtonConfig = ButtonConfig(
            type = ButtonType.SECONDARY,
            onClick = {
                if (state.scanComplete && state.scannedDocument == null) {
                    onTryAgain()
                } else {
                    onBack()
                }
            }),
        secondaryButtonConfig = ButtonConfig(
            type = ButtonType.PRIMARY,
            onClick = {
                if (state.scanComplete) {
                    onNext()
                } else {
                    onCapture()
                }
            })
    )

    val primaryButtonText = if (state.scanComplete) {
        R.string.passport_biometrics_next
    } else {
        R.string.passport_identification_capture
    }

    val secondaryButtonText = if (state.scanComplete && state.scannedDocument == null) {
        R.string.passport_biometrics_try_again
    } else {
        R.string.passport_identification_back
    }

    WrapStickyBottomContent(
        modifier = Modifier
            .fillMaxWidth()
            .padding(paddings),
        stickyBottomConfig = StickyBottomConfig(type = buttons, showDivider = false)
    ) { buttonConfigs ->
        buttonConfigs?.let { buttonConfig ->
            when (buttonConfig.type) {
                ButtonType.PRIMARY -> Text(stringResource(primaryButtonText))
                ButtonType.SECONDARY -> Text(stringResource(secondaryButtonText))
            }
        }
    }
}

private fun handleEffect(
    effect: Effect,
    hostNavController: NavController,
    context: Context,
    mrzScannerLauncher: ManagedActivityResultLauncher<Intent, ActivityResult>
) {
    when (effect) {
        is Navigation.GoBack -> hostNavController.popBackStack()
        is Navigation.StartMRZScanner -> mrzScannerLauncher.launch(
            DocumentScannerIntentHelper.createMrzScannerIntent(
                context
            )
        )

        is Navigation.SwitchScreen -> {
            hostNavController.navigate(effect.screenRoute)
        }
    }
}


@Composable
private fun Content(paddingValues: PaddingValues) {

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(paddingValues)
            .verticalScroll(rememberScrollState())
    ) {
        WrapText(
            text = stringResource(R.string.passport_identification_title),
            textConfig = TextConfig(
                style = MaterialTheme.typography.titleLarge.copy(
                    fontWeight = FontWeight.SemiBold,
                ),
                maxLines = Int.MAX_VALUE,
                isHeading = true
            ),
        )

        VSpacer.ExtraLarge()
        WrapText(
            text = stringResource(R.string.passport_identification_description),
            textConfig = TextConfig(
                style = MaterialTheme.typography.bodyLarge,
                maxLines = Int.MAX_VALUE
            ),
        )

        VSpacer.Large()
        BulletHolder(
            stringResource(R.string.passport_identification_step_first),
            stringResource(R.string.passport_identification_step_second)
        )

        VSpacer.Large()
        WrapText(
            text = stringResource(R.string.passport_identification_footer),
            textConfig = TextConfig(
                style = MaterialTheme.typography.bodyLarge,
                maxLines = Int.MAX_VALUE
            )
        )
    }
}


@Composable
fun VerifyYourDataContent(scannedDocument: ScannedDocument, paddingValues: PaddingValues) {

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(paddingValues)
            .verticalScroll(rememberScrollState())
    ) {
        WrapText(
            text = stringResource(R.string.passport_biometrics_verify_data),
            textConfig = TextConfig(
                style = MaterialTheme.typography.titleLarge.copy(
                    fontWeight = FontWeight.SemiBold
                ),
                maxLines = Int.MAX_VALUE,
                isHeading = true
            ),
        )

        VSpacer.Large()
        ElevatedCard(
            modifier = Modifier.fillMaxWidth(),
            elevation = CardDefaults.cardElevation(defaultElevation = SPACING_EXTRA_SMALL.dp),
            colors = CardDefaults.elevatedCardColors(containerColor = MaterialTheme.colorScheme.elevated),
            shape = RoundedCornerShape(size = SPACING_SMALL.dp)
        ) {

            Column(modifier = Modifier.padding(all = SPACING_LARGE.dp)) {

                WrapText(
                    text = stringResource(R.string.passport_biometrics_passport),
                    textConfig = TextConfig(
                        style = MaterialTheme.typography.titleLarge.copy(
                            fontWeight = FontWeight.SemiBold
                        ),
                        maxLines = Int.MAX_VALUE,
                        isHeading = true
                    ),
                )

                VSpacer.ExtraLarge()

                PassportImageOrFallback(scannedDocument)

                VSpacer.ExtraLarge()
                val labelId = R.string.passport_biometrics_dob
                PassportInfoWithLabel(labelId, formatDateForLocale(scannedDocument.dateOfBirth))

                VSpacer.ExtraLarge()
                val labelExpiry = R.string.passport_biometrics_doe
                PassportInfoWithLabel(labelExpiry, formatDateForLocale(scannedDocument.expiryDate))
            }
        }
    }
}

fun formatDateForLocale(dateString: String?): String {
    if (dateString.isNullOrEmpty()) return ""
    val inputFormatter = DateTimeFormatter.ofPattern("MM/dd/yyyy")
    val date = LocalDate.parse(dateString, inputFormatter)
    val locale = Locale.getDefault()
    val outputFormatter = DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM).withLocale(locale)
    return date.format(outputFormatter)
}

@Composable
private fun PassportInfoWithLabel(
    labelId: Int,
    text: String?,
) {
    WrapText(
        text = stringResource(labelId),
        textConfig = TextConfig(
            style = MaterialTheme.typography.bodyMedium
        )
    )

    VSpacer.Small()
    WrapText(
        text = text ?: stringResource(R.string.passport_biometrics_no_availability),
        textConfig = TextConfig(
            style = MaterialTheme.typography.bodyLarge.copy(
                fontWeight = FontWeight.SemiBold
            )
        )
    )
}

@Composable
private fun PassportImageOrFallback(scannedDocument: ScannedDocument) {
    if (scannedDocument is ScannedDocument.Passport) {
        scannedDocument.faceImage?.let { faceImage ->
            Image(
                painter = BitmapPainter(faceImage.asImageBitmap()),
                contentDescription = stringResource(R.string.content_description_passport_face_image),
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .size(150.dp),
                contentScale = ContentScale.Fit
            )
        } ?: Image(
            painter = painterResource(R.drawable.ic_logo_plain),
            contentDescription = stringResource(R.string.content_description_passport_face_image_placeholder),
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(8.dp))
                .size(150.dp),
            contentScale = ContentScale.Fit
        )
    } else {
        WrapImage(
            modifier = Modifier.size(64.dp),
            iconData = AppIcons.Id,
        )
    }
}

@Composable
@ThemeModePreviews
fun PassportIdentificationScreenPreview() {
    PreviewTheme {
        ContentScreen(
            navigatableAction = ScreenNavigateAction.NONE,
            stickyBottom = { paddingValues ->
                ActionButtons(
                    state = State(scanComplete = false),
                    paddings = paddingValues,
                )
            }
        ) { paddingValues ->
            Content(paddingValues = paddingValues)
        }
    }
}

@Composable
@ThemeModePreviews
fun VerifyYourDataContentPreview() {
    PreviewTheme {
        ContentScreen(
            navigatableAction = ScreenNavigateAction.NONE,
            stickyBottom = { paddingValues ->
                ActionButtons(
                    state = State(scanComplete = true),
                    paddings = paddingValues
                )
            }
        ) { paddingValues ->
            VerifyYourDataContent(
                scannedDocument = ScannedDocument.Passport(
                    dateOfBirth = "10/28/1983",
                    expiryDate = "01/31/2033",
                    faceImage = null
                ), paddingValues = paddingValues
            )
        }
    }
}
