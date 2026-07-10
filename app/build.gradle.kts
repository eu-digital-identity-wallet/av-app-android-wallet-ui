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

import java.util.Properties
import project.convention.logic.AppBuildType
import project.convention.logic.config.LibraryModule
import project.convention.logic.getProperty

plugins {
    id("project.android.application")
    id("project.android.application.compose")
}

android {

    ndkVersion = "28.0.0"

    signingConfigs {
        create("release") {

            storeFile = file("${rootProject.projectDir}/sign/keystore.jks")

            keyAlias = getProperty("androidKeyAlias") ?: System.getenv("ANDROID_KEY_ALIAS")
            keyPassword = getProperty("androidKeyPassword") ?: System.getenv("ANDROID_KEY_PASSWORD")
            storePassword =
                getProperty("androidKeyPassword") ?: System.getenv("ANDROID_KEY_PASSWORD")

            enableV2Signing = true
        }
    }

    defaultConfig {
        applicationId = "com.scytales.av"

        val versionProperties = Properties().apply {
            load(rootProject.file("version.properties").inputStream())
        }
        val explicitVersionCode = System.getenv("VERSION_CODE")?.toIntOrNull()
            ?: versionProperties.getProperty("VERSION_CODE")?.toIntOrNull()
        versionCode = explicitVersionCode ?: ((System.getenv("GITHUB_RUN_NUMBER")?.toIntOrNull() ?: 1) + 4)

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }
    }

    buildTypes {
        debug {
            isDebuggable = true
            isMinifyEnabled = false
            applicationIdSuffix = AppBuildType.DEBUG.applicationIdSuffix
        }
        release {
            isDebuggable = false
            isMinifyEnabled = true
            applicationIdSuffix = AppBuildType.RELEASE.applicationIdSuffix
            signingConfig = signingConfigs.getByName("release")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    namespace = "eu.europa.ec.av"
}

dependencies {
    implementation(project(LibraryModule.AssemblyLogic.path))
    "baselineProfile"(project(LibraryModule.BaselineProfileLogic.path))
}
