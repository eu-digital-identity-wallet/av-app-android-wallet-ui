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

import project.convention.logic.config.LibraryModule
import project.convention.logic.kover.KoverExclusionRules
import project.convention.logic.kover.excludeFromKoverReport

plugins {
    id("project.android.library")
}

android {
    namespace = "eu.europa.ec.passportscanner"

    buildFeatures {
        viewBinding = true
    }
}

moduleConfig {
    module = LibraryModule.PassportScanner
}

configurations.all {
    exclude(group = "org.bouncycastle", module = "bcprov-jdk15on")
}

dependencies {
    // Project dependencies
    implementation(project(LibraryModule.BusinessLogic.path))
    implementation(project(LibraryModule.ResourcesLogic.path))

    // Test dependencies
    testImplementation(project(LibraryModule.TestLogic.path))

    implementation(files("libs/jj2000_imageutil.jar"))

    // Core Android dependencies
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.material)

    // ML Kit dependencies
    implementation(libs.mlkit.text.recognition)

    // CameraX
    implementation(libs.androidx.camera.core)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)

    // Guava for ListenableFuture (required by CameraX with flavors)
    implementation("com.google.guava:guava:31.1-android")

    // JSON processing
    implementation(libs.gson)
    implementation(libs.json.path)
    implementation(libs.json.flattener)

    // NFC dependencies
    implementation(libs.jmrtd)
    implementation(libs.spongycastle.prov)
    implementation(libs.scuba.sc.android)
    implementation(libs.cert.cvc)

    // WSQ
    implementation(libs.jnbis)

    // Utilities
    implementation("commons-codec:commons-codec:1.19.0")

    // RxJava
    implementation("io.reactivex.rxjava2:rxandroid:2.1.1")
    implementation("io.reactivex.rxjava2:rxjava:2.2.21")

    // Browser (for Custom Tabs)
    implementation(libs.androidx.browser)

    // JWT
    api("io.jsonwebtoken:jjwt-api:0.13.0")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.13.0")
    runtimeOnly("io.jsonwebtoken:jjwt-orgjson:0.13.0") {
        exclude(group = "org.json", module = "json") // provided by Android natively
    }
    implementation("io.jsonwebtoken:jjwt-gson:0.13.0")
}

excludeFromKoverReport(
    excludedClasses = KoverExclusionRules.PassportScanner.classes,
    excludedPackages = KoverExclusionRules.PassportScanner.packages,
)
