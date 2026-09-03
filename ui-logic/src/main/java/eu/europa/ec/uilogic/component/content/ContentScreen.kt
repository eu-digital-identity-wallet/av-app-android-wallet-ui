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

package eu.europa.ec.uilogic.component.content

import android.content.Intent
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.union
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.wrapContentSize
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FabPosition
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.platform.SoftwareKeyboardController
import androidx.compose.ui.zIndex
import eu.europa.ec.uilogic.component.AppIcons
import eu.europa.ec.uilogic.component.IconDataUi
import eu.europa.ec.uilogic.component.SystemBroadcastReceiver
import eu.europa.ec.uilogic.component.loader.LoadingIndicator
import eu.europa.ec.uilogic.component.preview.PreviewTheme
import eu.europa.ec.uilogic.component.preview.ThemeModePreviews
import eu.europa.ec.uilogic.component.utils.MAX_TOOLBAR_ACTIONS
import eu.europa.ec.uilogic.component.utils.TopSpacing
import eu.europa.ec.uilogic.component.utils.Z_STICKY
import eu.europa.ec.uilogic.component.utils.screenPaddings
import eu.europa.ec.uilogic.component.utils.stickyBottomPaddings
import eu.europa.ec.uilogic.component.wrap.WrapIcon
import eu.europa.ec.uilogic.component.wrap.WrapIconButton

data class ToolbarActionUi(
    val icon: IconDataUi,
    val order: Int = 100,
    val enabled: Boolean = true,
    val customTint: Color? = null,
    val clickable: Boolean = true,
    val throttleClicks: Boolean = true,
    val onClick: () -> Unit,
)

data class ToolbarConfig(
    val title: String = "",
    val actions: List<ToolbarActionUi> = listOf()
)

enum class ScreenNavigateAction {
    BACKABLE, CANCELABLE, NONE
}

enum class ImePaddingConfig {
    NO_PADDING, WITH_BOTTOM_BAR, ONLY_CONTENT
}

data class BroadcastAction(val intentFilters: List<String>, val callback: (Intent?) -> Unit)

@Composable
fun ContentScreen(
    isLoading: Boolean = false,
    toolBarConfig: ToolbarConfig? = null,
    navigatableAction: ScreenNavigateAction = ScreenNavigateAction.BACKABLE,
    onBack: (() -> Unit)? = null,
    topBar: @Composable (() -> Unit)? = null,
    bottomBar: @Composable (() -> Unit)? = null,
    stickyBottom: @Composable ((PaddingValues) -> Unit)? = null,
    fab: @Composable () -> Unit = {},
    fabPosition: FabPosition = FabPosition.End,
    snackbarHost: @Composable () -> Unit = {},
    contentErrorConfig: ContentErrorConfig? = null,
    broadcastAction: BroadcastAction? = null,
    imePaddingConfig: ImePaddingConfig = ImePaddingConfig.NO_PADDING,
    bodyContent: @Composable (PaddingValues) -> Unit
) {
    val keyboardController = LocalSoftwareKeyboardController.current
    val layoutDirection = LocalLayoutDirection.current

    val hasToolBar = contentErrorConfig != null
            || navigatableAction != ScreenNavigateAction.NONE
            || topBar != null
            || toolBarConfig?.actions?.isNotEmpty() == true
    val topSpacing = if (hasToolBar) TopSpacing.WithToolbar else TopSpacing.WithoutToolbar

    val topBarInsets = WindowInsets.systemBars
        .union(WindowInsets.displayCutout)
        .only(WindowInsetsSides.Horizontal + WindowInsetsSides.Top)

    Scaffold(
        topBar = {
            if (topBar != null && contentErrorConfig == null) {
                Box(
                    modifier = Modifier
                        .wrapContentSize()
                        .windowInsetsPadding(topBarInsets)
                ) {
                    topBar()
                }
            } else if (hasToolBar) {
                DefaultToolBar(
                    navigatableAction = contentErrorConfig?.let {
                        ScreenNavigateAction.CANCELABLE
                    } ?: navigatableAction,
                    onBack = contentErrorConfig?.onCancel ?: onBack,
                    keyboardController = keyboardController,
                    toolbarConfig = toolBarConfig,
                    windowInsets = topBarInsets,
                )
            }
        },
        bottomBar = {
            bottomBar?.let {
                Box(
                    modifier = Modifier
                        .wrapContentSize()
                        .then(
                            if (imePaddingConfig == ImePaddingConfig.WITH_BOTTOM_BAR) {
                                Modifier.imePadding()
                            } else {
                                Modifier
                            }
                        )
                ) {
                    bottomBar()
                }
            }
        },
        floatingActionButton = fab,
        floatingActionButtonPosition = fabPosition,
        snackbarHost = snackbarHost,
        contentWindowInsets = WindowInsets.systemBars.union(WindowInsets.displayCutout),
    ) { padding ->

        val screenPaddingsIgnoringSticky = screenPaddings(
            hasStickyBottom = false,
            append = padding,
            layoutDirection = layoutDirection,
            topSpacing = topSpacing
        )

        Box(
            modifier = Modifier.fillMaxSize()
        ) {

            if (contentErrorConfig != null) {
                ContentError(
                    config = contentErrorConfig,
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(screenPaddingsIgnoringSticky)
                )
            } else {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .then(
                            if (imePaddingConfig == ImePaddingConfig.ONLY_CONTENT) {
                                Modifier.imePadding()
                            } else {
                                Modifier
                            }
                        )
                ) {

                    Box(modifier = Modifier.weight(1f)) {
                        bodyContent(
                            screenPaddings(
                                hasStickyBottom = stickyBottom != null,
                                append = padding,
                                layoutDirection = layoutDirection,
                                topSpacing = topSpacing
                            )
                        )
                    }

                    stickyBottom?.let { stickyBottomContent ->
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .windowInsetsPadding(
                                    WindowInsets.navigationBars.only(WindowInsetsSides.Bottom)
                                )
                                .zIndex(Z_STICKY),
                            contentAlignment = Alignment.Center
                        ) {
                            stickyBottomContent(
                                stickyBottomPaddings(
                                    contentScreenPaddings = screenPaddingsIgnoringSticky,
                                    layoutDirection = layoutDirection
                                )
                            )
                        }
                    }
                }

                if (isLoading) LoadingIndicator()
            }
        }
    }

    BackHandler(enabled = true) {
        contentErrorConfig?.let {
            contentErrorConfig.onCancel()
        } ?: onBack?.invoke()
    }

    broadcastAction?.let {
        SystemBroadcastReceiver(
            intentFilters = it.intentFilters
        ) { intent ->
            it.callback(intent)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DefaultToolBar(
    navigatableAction: ScreenNavigateAction,
    onBack: (() -> Unit)?,
    keyboardController: SoftwareKeyboardController?,
    toolbarConfig: ToolbarConfig?,
    windowInsets: WindowInsets,
) {

    TopAppBar(
        windowInsets = windowInsets,
        title = {
            Text(
                text = toolbarConfig?.title.orEmpty(),
                color = MaterialTheme.colorScheme.primary
            )
        },
        navigationIcon = {
            // Check if we should add back/close button.
            if (navigatableAction != ScreenNavigateAction.NONE) {
                val navigationIcon = when (navigatableAction) {
                    ScreenNavigateAction.CANCELABLE -> AppIcons.Close
                    else -> AppIcons.ArrowBack
                }

                ToolbarIcon(
                    toolbarAction = ToolbarActionUi(
                        icon = navigationIcon,
                        onClick = {
                            onBack?.invoke()
                            keyboardController?.hide()
                        }
                    )
                )
            }
        },
        // Add toolbar actions.
        actions = {
            ToolBarActions(toolBarActions = toolbarConfig?.actions)
        }
    )
}

@Composable
internal fun ToolBarActions(
    toolBarActions: List<ToolbarActionUi>?
) {
    toolBarActions?.let { actions ->

        var dropDownMenuExpanded by remember { mutableStateOf(false) }

        // Show first [MAX_TOOLBAR_ACTIONS] actions.
        actions
            .sortedByDescending { it.order }
            .take(MAX_TOOLBAR_ACTIONS)
            .map { visibleToolbarAction ->
                ToolbarIcon(toolbarAction = visibleToolbarAction)
            }

        // Check if there are more actions to show.
        if (actions.size > MAX_TOOLBAR_ACTIONS) {
            Box {
                ToolbarIcon(
                    toolbarAction = ToolbarActionUi(
                        icon = AppIcons.VerticalMore,
                        onClick = { dropDownMenuExpanded = !dropDownMenuExpanded },
                        enabled = true,
                    )
                )
                DropdownMenu(
                    expanded = dropDownMenuExpanded,
                    onDismissRequest = { dropDownMenuExpanded = false }
                ) {
                    actions
                        .sortedByDescending { it.order }
                        .drop(MAX_TOOLBAR_ACTIONS)
                        .map { dropDownMenuToolbarAction ->
                            ToolbarIcon(toolbarAction = dropDownMenuToolbarAction)
                        }
                }
            }
        }
    }
}

@Composable
private fun ToolbarIcon(toolbarAction: ToolbarActionUi) {
    val customIconTint = toolbarAction.customTint
        ?: MaterialTheme.colorScheme.onSurface

    if (toolbarAction.clickable) {
        WrapIconButton(
            iconData = toolbarAction.icon,
            onClick = toolbarAction.onClick,
            enabled = toolbarAction.enabled,
            customTint = customIconTint,
            throttleClicks = toolbarAction.throttleClicks
        )
    } else {
        WrapIcon(
            modifier = Modifier.minimumInteractiveComponentSize(),
            iconData = toolbarAction.icon,
            enabled = toolbarAction.enabled,
            customTint = customIconTint,
        )
    }
}

@ThemeModePreviews
@Composable
private fun ToolbarIconClickablePreview() {
    PreviewTheme {
        val action = ToolbarActionUi(
            icon = AppIcons.Verified,
            onClick = {},
            enabled = true,
            clickable = true,
        )

        ToolbarIcon(toolbarAction = action)
    }
}

@ThemeModePreviews
@Composable
private fun ToolbarIconNotClickablePreview() {
    PreviewTheme {
        val action = ToolbarActionUi(
            icon = AppIcons.Verified,
            onClick = {},
            enabled = true,
            clickable = false,
        )

        ToolbarIcon(toolbarAction = action)
    }
}

@ThemeModePreviews
@Composable
private fun ToolBarActionsWithFourActionsPreview() {
    PreviewTheme {
        val toolBarActions = listOf(
            ToolbarActionUi(
                icon = AppIcons.Verified,
                onClick = {},
                enabled = true,
                clickable = true,
            ),
            ToolbarActionUi(
                icon = AppIcons.Verified,
                onClick = {},
                enabled = false,
                clickable = true,
            ),
            ToolbarActionUi(
                icon = AppIcons.Verified,
                onClick = {},
                enabled = true,
                clickable = false,
            ),
            ToolbarActionUi(
                icon = AppIcons.Verified,
                onClick = {},
                enabled = false,
                clickable = false,
            )
        )

        Row {
            ToolBarActions(toolBarActions)
        }
    }
}