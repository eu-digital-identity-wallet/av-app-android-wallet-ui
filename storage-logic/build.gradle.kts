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
    id("project.androidx.room")
}

extensions.configure<LibraryExtension>("android") {
    namespace = "eu.europa.ec.storagelogic"
}

moduleConfig {
    module = LibraryModule.StorageLogic
}

dependencies {
    implementation(project(LibraryModule.BusinessLogic.path))
    implementation(libs.sqlcipher)
}

excludeFromKoverReport(
    excludedClasses = KoverExclusionRules.StorageLogic.classes,
    excludedPackages = KoverExclusionRules.StorageLogic.packages,
)