import org.jetbrains.kotlin.config.KotlinCompilerVersion

plugins {
    id("com.android.library")
    id("kotlin-android")
}

android {
    compileSdkVersion(28)
    defaultConfig {
        minSdkVersion(19)
        targetSdkVersion(28)
        versionCode = 1
        versionName = "0.2.0"
        testInstrumentationRunner = "android.support.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android.txt"), "proguard-rules.pro")
        }
    }
}

dependencies {
    implementation(kotlin("stdlib-jdk8", KotlinCompilerVersion.VERSION))

    implementation("com.goterl.lazycode:lazysodium-android:3.3.0@aar")
    implementation("net.java.dev.jna:jna:4.5.2@aar")

    testImplementation("junit:junit:4.12")

    androidTestImplementation("com.android.support.test:runner:1.0.2")
    androidTestImplementation("com.android.support.test.espresso:espresso-core:3.0.2")
}