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

import com.android.build.api.dsl.LibraryExtension
import project.convention.logic.config.LibraryModule
import project.convention.logic.kover.KoverExclusionRules
import project.convention.logic.kover.excludeFromKoverReport

plugins {
    id("project.android.library")
    id("project.android.library.compose")
}

extensions.configure<LibraryExtension>("android") {
    namespace = "eu.europa.ec.uilogic"
}

moduleConfig {
    module = LibraryModule.UiLogic
}

dependencies {
    implementation(project(LibraryModule.ResourcesLogic.path))
    implementation(project(LibraryModule.BusinessLogic.path))
    implementation(project(LibraryModule.AnalyticsLogic.path))
    implementation(project(LibraryModule.CoreLogic.path))
    implementation(project(LibraryModule.StorageLogic.path))

    implementation(libs.zxing)
    implementation(libs.gson)

    testImplementation(project(LibraryModule.TestLogic.path))
    testImplementation(libs.androidx.compose.ui.test)
}

excludeFromKoverReport(
    excludedClasses = KoverExclusionRules.UiLogic.classes,
    excludedPackages = KoverExclusionRules.UiLogic.packages,
)