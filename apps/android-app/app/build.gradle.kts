import com.android.build.api.variant.ApplicationAndroidComponentsExtension
import org.gradle.api.GradleException
import org.gradle.api.file.Directory
import org.gradle.api.provider.Provider
import java.io.File

private fun readWorkspacePackageVersion(workspaceRoot: File): String {
    val cargoToml = File(workspaceRoot, "Cargo.toml")
    if (!cargoToml.isFile) {
        throw GradleException("Workspace Cargo.toml not found at ${cargoToml.absolutePath}")
    }

    var inWorkspacePackage = false
    var workspaceVersion: String? = null
    cargoToml.useLines { lines ->
        for (rawLine in lines) {
            val line = rawLine.trim()
            if (line.startsWith("[") && line.endsWith("]")) {
                inWorkspacePackage = line == "[workspace.package]"
                continue
            }

            if (!inWorkspacePackage) {
                continue
            }

            val match = Regex("""^version\s*=\s*\"([^\"]+)\"$""").matchEntire(line)
            if (match != null) {
                workspaceVersion = match.groupValues[1]
                break
            }
        }
    }

    return workspaceVersion
        ?: throw GradleException("workspace.package.version not found in ${cargoToml.absolutePath}")
}

private fun readGitDescribe(workspaceRoot: File): String {
    val process = ProcessBuilder(
        "git",
        "describe",
        "--tags",
        "--always",
        "--dirty=-dirty",
        "--abbrev=12",
    )
        .directory(workspaceRoot)
        .redirectErrorStream(true)
        .start()

    val output = process.inputStream.bufferedReader().use { it.readText().trim() }
    val exitCode = process.waitFor()
    if (exitCode != 0 || output.isBlank()) {
        throw GradleException(
            "Failed to read git build revision for Android version display from ${workspaceRoot.absolutePath}",
        )
    }

    return output
}

private fun escapeBuildConfigString(value: String): String =
    value
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .replace("\r", "\\r")

private fun parseVersionParts(value: String): List<Int> =
    value.split(".", "-", "_").map { it.toIntOrNull() ?: 0 }

private fun compareVersionParts(a: List<Int>, b: List<Int>): Int {
    val size = maxOf(a.size, b.size)
    for (i in 0 until size) {
        val av = a.getOrElse(i) { 0 }
        val bv = b.getOrElse(i) { 0 }
        if (av != bv) {
            return av.compareTo(bv)
        }
    }
    return 0
}

private fun findLatestSideBySideNdk(sdkDir: File): File? {
    val ndkRoot = File(sdkDir, "ndk")
    if (!ndkRoot.isDirectory) return null
    return ndkRoot.listFiles { file -> file.isDirectory }
        ?.maxWithOrNull { a, b ->
            compareVersionParts(parseVersionParts(a.name), parseVersionParts(b.name))
        }
}

private fun resolveInstalledNdk(
    ndkDirectoryProvider: Provider<Directory>,
    sdkDirectoryProvider: Provider<Directory>
): File? {
    val ndkFromAgp = runCatching { ndkDirectoryProvider.get().asFile }.getOrNull()
    if (ndkFromAgp != null && ndkFromAgp.isDirectory) return ndkFromAgp

    val sdkDir = runCatching { sdkDirectoryProvider.get().asFile }.getOrNull() ?: return null
    val latestSideBySide = findLatestSideBySideNdk(sdkDir)
    if (latestSideBySide != null) return latestSideBySide

    val ndkBundle = File(sdkDir, "ndk-bundle")
    return ndkBundle.takeIf { it.isDirectory }
}

val workspaceRoot = rootDir.parentFile?.parentFile ?: rootDir
val workspaceVersion = readWorkspacePackageVersion(workspaceRoot)
val gitBuildRevision = readGitDescribe(workspaceRoot)
val longVersion = "${workspaceVersion}\nBuild revision: ${gitBuildRevision}"

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "io.ironmesh.android"
    compileSdk = 34

    defaultConfig {
        applicationId = "io.ironmesh.android"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = workspaceVersion
        buildConfigField(
            "String",
            "GIT_BUILD_REVISION",
            "\"${escapeBuildConfigString(gitBuildRevision)}\"",
        )
        buildConfigField(
            "String",
            "LONG_VERSION",
            "\"${escapeBuildConfigString(longVersion)}\"",
        )

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDir(layout.buildDirectory.dir("generated/rustJniLibs"))
        }
    }
}

val androidComponents = extensions.getByType<ApplicationAndroidComponentsExtension>()
val ndkDirectoryProvider = androidComponents.sdkComponents.ndkDirectory
val sdkDirectoryProvider = androidComponents.sdkComponents.sdkDirectory

val buildRust = tasks.register<Exec>("buildRust") {
    group = "build"

    val isRelease = gradle.startParameter.taskNames.any { it.contains("release", ignoreCase = true) }
    val outDir = layout.buildDirectory.dir("generated/rustJniLibs").get().asFile

    workingDir = workspaceRoot

    doFirst {
        outDir.mkdirs()

        val ndkDir = resolveInstalledNdk(
            ndkDirectoryProvider = ndkDirectoryProvider,
            sdkDirectoryProvider = sdkDirectoryProvider
        )
            ?: throw GradleException(
                "Android NDK not found under the Android SDK. Install 'NDK (Side by side)' in Android Studio SDK Manager."
            )

        environment("ANDROID_NDK_HOME", ndkDir.absolutePath)
        environment("NDK_HOME", ndkDir.absolutePath)
    }

    executable("cargo")

    val argsList = mutableListOf<String>()
    argsList.addAll(listOf("ndk", "-t", "arm64-v8a", "-t", "x86_64", "-o", outDir.absolutePath, "build", "-p", "android-app"))
    if (isRelease) {
        argsList.add("--release")
    }

    args(argsList)
}

tasks.matching { it.name.startsWith("merge") && it.name.endsWith("JniLibFolders") }
    .configureEach {
        dependsOn(buildRust)
    }

dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.06.00"))
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.4")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.4")
    implementation("androidx.activity:activity-compose:1.9.1")
    implementation("androidx.browser:browser:1.8.0")
    implementation("androidx.work:work-runtime-ktx:2.9.1")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("com.google.android.material:material:1.12.0")

    implementation("com.journeyapps:zxing-android-embedded:4.3.0")

    implementation("com.squareup.retrofit2:retrofit:2.11.0")
    implementation("com.squareup.retrofit2:converter-moshi:2.11.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")
    implementation("com.squareup.moshi:moshi-kotlin:1.15.1")

    androidTestImplementation("org.jetbrains.kotlin:kotlin-stdlib:1.9.24")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.1")
    testImplementation("junit:junit:4.13.2")

    debugImplementation("androidx.compose.ui:ui-tooling")
}
