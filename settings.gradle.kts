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

pluginManagement {
    val toolChainResolverVersion = extra["toolChainResolverVersion"] as String
    plugins {
        id("org.gradle.toolchains.foojay-resolver-convention") version toolChainResolverVersion
    }
    includeBuild("build-logic")
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    @Suppress("UnstableApiUsage")
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    @Suppress("UnstableApiUsage")
    repositories {
        google()
        mavenCentral()
        maven {
            url = uri("https://central.sonatype.com/repository/maven-snapshots/")
            mavenContent { snapshotsOnly() }
        }
        maven {
            url = uri("https://jitpack.io")
        }
        mavenLocal()
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention")
}

rootProject.name = "AV Wallet"
include(":app")
include(":business-logic")
include(":ui-logic")
include(":network-logic")
include(":resources-logic")
include(":assembly-logic")
include(":startup-feature")
include(":test-logic")
include(":test-feature")
include(":common-feature")
include(":onboarding-feature")
include(":presentation-feature")
include(":issuance-feature")
include(":analytics-logic")
include(":baseline-profile")
include(":authentication-logic")
include(":core-logic")
include(":storage-logic")
include(":landing-feature")
include(":passport-scanner")
