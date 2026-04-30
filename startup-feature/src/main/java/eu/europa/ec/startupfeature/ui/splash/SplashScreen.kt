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

package eu.europa.ec.startupfeature.ui.splash

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import eu.europa.ec.resourceslogic.R
import eu.europa.ec.uilogic.component.AppIcons
import eu.europa.ec.uilogic.component.preview.PreviewTheme
import eu.europa.ec.uilogic.component.preview.ThemeModePreviews
import eu.europa.ec.uilogic.component.utils.HSpacer
import eu.europa.ec.uilogic.component.utils.OneTimeLaunchedEffect
import eu.europa.ec.uilogic.component.utils.SPACING_LARGE
import eu.europa.ec.uilogic.component.utils.SPACING_SMALL_PLUS
import eu.europa.ec.uilogic.component.utils.VSpacer
import eu.europa.ec.uilogic.component.wrap.TextConfig
import eu.europa.ec.uilogic.component.wrap.WrapImage
import eu.europa.ec.uilogic.component.wrap.WrapText
import eu.europa.ec.uilogic.extension.getAppVersionCode
import eu.europa.ec.uilogic.extension.getAppVersionName
import eu.europa.ec.uilogic.navigation.ModuleRoute
import eu.europa.ec.uilogic.navigation.StartupScreens
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
fun SplashScreen(
    navController: NavController,
    viewModel: SplashViewModel,
) {
    val context = LocalContext.current
    val versionCode = context.getAppVersionCode()
    val versionName = context.getAppVersionName()
    Content(
        effectFlow = viewModel.effect,
        versionName = versionName,
        versionCode = versionCode,
        onNavigationRequested = { navigationEffect ->
            handleNavigationEffects(navigationEffect, navController)
        }
    )

    OneTimeLaunchedEffect {
        viewModel.setEvent(Event.Initialize)
    }
}

private fun handleNavigationEffects(
    navigationEffect: Effect.Navigation,
    navController: NavController,
) {
    when (navigationEffect) {
        is Effect.Navigation.SwitchModule -> {
            navController.navigate(navigationEffect.moduleRoute.route) {
                popUpTo(ModuleRoute.StartupModule.route) { inclusive = true }
            }
        }

        is Effect.Navigation.SwitchScreen -> {
            navController.navigate(navigationEffect.route) {
                popUpTo(StartupScreens.Splash.screenRoute) { inclusive = true }
            }
        }
    }
}

@Composable
private fun Content(
    effectFlow: Flow<Effect>,
    versionName: String,
    versionCode: Long,
    onNavigationRequested: (navigationEffect: Effect.Navigation) -> Unit,
) {

    Column(
        modifier = Modifier
            .fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(modifier = Modifier.weight(0.3f))
        MapTitleAndLogo()
        Spacer(modifier = Modifier.weight(1f))
        VersionInfo(versionName, versionCode)
        Footer()
    }


    LaunchedEffect(Unit) {
        effectFlow.onEach { effect ->
            when (effect) {
                is Effect.Navigation -> onNavigationRequested(effect)
            }
        }.collect()
    }
}

@Composable
private fun MapTitleAndLogo() {
    Box(
        modifier = Modifier.padding(horizontal = SPACING_LARGE.dp),
        contentAlignment = Alignment.Center,
    ) {
        WrapImage(
            modifier = Modifier
                .fillMaxWidth(),
            iconData = AppIcons.EuMap,
            contentScale = ContentScale.FillWidth,
        )
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            WrapImage(
                modifier = Modifier.height(80.dp),
                iconData = AppIcons.LogoPlain,
                contentScale = ContentScale.FillHeight
            )
            VSpacer.ExtraLarge()
            WrapText(
                modifier = Modifier
                    .fillMaxWidth(),
                text = stringResource(R.string.splash_screen_title),
                textConfig = TextConfig(
                    style = MaterialTheme.typography.displaySmall.copy(
                        brush = Brush.verticalGradient(
                            colors = listOf(
                                MaterialTheme.colorScheme.primary,
                                Color(0xFF0A215F),
                            ),
                        )
                    ),
                    textAlign = TextAlign.Center
                )
            )
        }
    }
}

@Composable
private fun Footer() {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(
                RoundedCornerShape(
                    topStart = 24.dp,
                    topEnd = 24.dp,
                    bottomEnd = 0.dp,
                    bottomStart = 0.dp
                )
            )
            .background(MaterialTheme.colorScheme.primary)
            .padding(SPACING_SMALL_PLUS.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Spacer(modifier = Modifier.weight(0.2f))
        WrapText(
            modifier = Modifier,
            text = stringResource(R.string.splash_screen_sponsors),
            textConfig = TextConfig(
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onPrimary,
            ),
        )
        HSpacer.Large()
        WrapImage(
            iconData = AppIcons.ScytalesLogo
        )
        HSpacer.Large()
        WrapImage(
            iconData = AppIcons.TelekomLogo
        )
        Spacer(modifier = Modifier.weight(1f))
    }
}

@Composable
private fun VersionInfo(versionName: String, versionCode: Long) {
    WrapText(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 8.dp),
        text = "$versionName($versionCode)",
        textConfig = TextConfig(
            style = MaterialTheme.typography.bodySmall,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.primary
        )
    )
}

@ThemeModePreviews
@Composable
private fun SplashScreenPreview() {
    PreviewTheme {
        Content(
            effectFlow = Channel<Effect>().receiveAsFlow(),
            versionName = "1.0.0",
            versionCode = 5,
            onNavigationRequested = {}
        )
    }
}