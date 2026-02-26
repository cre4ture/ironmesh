plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val rustAbiTargets = listOf("arm64-v8a", "x86_64")
val rustJniOutDir = layout.buildDirectory.dir("generated/rustJniLibs")
val workspaceRoot = rootProject.layout.projectDirectory.dir("../../..").asFile
val rustManifestPath = "apps/android-app/Cargo.toml"

val buildRustJniLibs by tasks.registering(Exec::class) {
    group = "build"
    description = "Build Rust JNI library for Android ABIs via cargo-ndk"
    workingDir = workspaceRoot

    doFirst {
        rustJniOutDir.get().asFile.mkdirs()
        
        // Access NDK directory only at execution time to avoid configuration errors
        val ndkDir = project.extensions.getByType<com.android.build.gradle.BaseExtension>().ndkDirectory
        if (ndkDir == null || !ndkDir.exists()) {
            throw GradleException(
                "NDK is not installed or not found. Please ensure 'ndkVersion' is set correctly " +
                "in build.gradle.kts and installed via the Android SDK Manager."
            )
        }
        environment("ANDROID_NDK_HOME", ndkDir.absolutePath)
        
        val releaseBuild = gradle.startParameter.taskNames.any {
            it.contains("Release", ignoreCase = true)
        }

        val args = mutableListOf("cargo", "ndk", "-o", rustJniOutDir.get().asFile.absolutePath)
        rustAbiTargets.forEach { abi ->
            args.add("-t")
            args.add(abi)
        }
        args.add("build")
        args.add("--manifest-path")
        args.add(rustManifestPath)
        if (releaseBuild) {
            args.add("--release")
        }
        commandLine(args)
    }
}

android {
    namespace = "io.ironmesh.android"
    compileSdk = 34
    
    // Ensure AGP knows which version to use/download
    ndkVersion = "26.1.10909125"

    defaultConfig {
        applicationId = "io.ironmesh.android"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            abiFilters += rustAbiTargets
        }
    }

    buildTypes {
        release {
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
            jniLibs.srcDir(rustJniOutDir)
        }
    }
}

tasks.named("preBuild") {
    dependsOn(buildRustJniLibs)
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")

    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("com.google.android.material:material:1.12.0")

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.4")
    implementation("androidx.activity:activity-compose:1.9.1")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.4")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    implementation("com.squareup.retrofit2:retrofit:2.11.0")
    implementation("com.squareup.retrofit2:converter-moshi:2.11.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")
    implementation("com.squareup.moshi:moshi-kotlin:1.15.1")

    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
