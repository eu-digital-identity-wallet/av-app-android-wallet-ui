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

package project.convention.logic

import com.android.build.api.dsl.CommonExtension
import org.gradle.api.Project
import org.gradle.kotlin.dsl.dependencies
import org.gradle.kotlin.dsl.withType
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

/**
 * Configure Compose-specific options
 */
internal fun Project.configureAndroidCompose(
    commonExtension: CommonExtension,
) {
    commonExtension.apply {

        buildFeatures.compose = true

        dependencies {

            val bom = libs.findLibrary("androidx-compose-bom").get()

            add("implementation", platform(bom))

            add("implementation", libs.findLibrary("coil.kt").get())
            add("implementation", libs.findLibrary("coil.kt.compose").get())
            add("implementation", libs.findLibrary("coil.kt.svg").get())
            add("implementation", libs.findLibrary("coil-kt-network-okhttp").get())

            add("implementation", libs.findLibrary("androidx-navigation-compose").get())

            add("implementation", libs.findLibrary("androidx.lifecycle.runtimeCompose").get())
            add("implementation", libs.findLibrary("androidx.lifecycle.viewModelCompose").get())

            add("implementation", libs.findLibrary("accompanist-permissions").get())

            add("implementation", libs.findLibrary("compose-cloudy").get())

            add("implementation", libs.findLibrary("androidx.constraintlayout.compose").get())
            add("implementation", libs.findLibrary("androidx.compose.ui.tooling.preview").get())
            add("debugImplementation", libs.findLibrary("androidx.compose.ui.tooling").get())

            if (project.projectDir.resolve("src/androidTest").exists()) {
                add("androidTestImplementation", platform(bom))
            }
            add("debugImplementation", libs.findLibrary("androidx.compose.ui.testManifest").get())
            add("debugImplementation", libs.findLibrary("androidx.compose.ui.tooling").get())
            add("testImplementation", libs.findLibrary("robolectric").get())
        }

        testOptions.unitTests.apply {
            isIncludeAndroidResources = true
            isReturnDefaultValues = true
        }
    }

    tasks.withType<KotlinCompile>().configureEach {
        compilerOptions {
            freeCompilerArgs.addAll(buildComposeMetricsParameters())
        }
    }
}

private fun Project.buildComposeMetricsParameters(): List<String> {
    val metricParameters = mutableListOf<String>()
    val enableMetricsProvider = project.providers.gradleProperty("enableComposeCompilerMetrics")
    val relativePath = projectDir.relativeTo(rootDir)

    val enableMetrics = (enableMetricsProvider.orNull == "true")
    if (enableMetrics) {
        val metricsFolder =
            rootProject.layout.buildDirectory.get().asFile.resolve("compose-metrics")
                .resolve(relativePath)
        metricParameters.add("-P")
        metricParameters.add(
            "plugin:androidx.compose.compiler.plugins.kotlin:metricsDestination=" + metricsFolder.absolutePath
        )
    }

    val enableReportsProvider = project.providers.gradleProperty("enableComposeCompilerReports")
    val enableReports = (enableReportsProvider.orNull == "true")
    if (enableReports) {
        val reportsFolder =
            rootProject.layout.buildDirectory.get().asFile.resolve("compose-reports")
                .resolve(relativePath)
        metricParameters.add("-P")
        metricParameters.add(
            "plugin:androidx.compose.compiler.plugins.kotlin:reportsDestination=" + reportsFolder.absolutePath
        )
    }
    return metricParameters.toList()
}
