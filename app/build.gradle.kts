import org.jetbrains.kotlin.config.KotlinCompilerVersion
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import de.mannodermaus.gradle.plugins.junit5.*

plugins {
    id("com.android.library")
    id("kotlin-android")
    id("org.jetbrains.dokka") version "0.9.16"
}

android {
    compileSdkVersion(28)
    defaultConfig {
        minSdkVersion(26)
        targetSdkVersion(28)
        versionCode = 1
        versionName = "1"
        testInstrumentationRunner = "android.support.test.runner.AndroidJUnitRunner"
        testInstrumentationRunnerArgument("runnerBuilder", "de.mannodermaus.junit5.AndroidJUnit5Builder")
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android.txt"), "proguard-rules.pro")
        }
    }

    sourceSets {
        getByName("androidTest").java.srcDirs("src/androidTest/kotlin")
        getByName("test").java.srcDirs("src/test/kotlin")
    }

    compileOptions {
        setSourceCompatibility(JavaVersion.VERSION_1_8)
        setTargetCompatibility(JavaVersion.VERSION_1_8)
    }

    tasks.withType<KotlinCompile> {
        kotlinOptions {
            jvmTarget = "1.8"
        }
    }

    packagingOptions {
        exclude("META-INF/LICENSE.md")
        exclude("META-INF/LICENSE-notice.md")
        exclude("**/*.kotlin_module")
        exclude("**/*.version")
        exclude("**/kotlin/**")
        exclude("**/*.txt")
        exclude("**/*.xml")
        exclude("**/*.properties")
    }

    testOptions {
        unitTests.apply {
            isReturnDefaultValues = true
            isIncludeAndroidResources = true
        }
    }
}

val dokka by tasks.getting(org.jetbrains.dokka.gradle.DokkaTask::class) {    
    outputFormat = "html"
    outputDirectory = "$buildDir/javadoc"
}

dependencies {
    implementation(kotlin("stdlib-jdk8", KotlinCompilerVersion.VERSION))

    implementation("com.goterl.lazycode:lazysodium-android:3.3.0@aar")
    implementation("net.java.dev.jna:jna:4.5.2@aar")

    implementation("at.favre.lib:hkdf:1.0.0:@jar")
    implementation("commons-codec:commons-codec:1.11:@jar")
    
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.2.0")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.2.0")
    testImplementation("org.junit.jupiter:junit-jupiter-params:5.2.0")

    androidTestImplementation("org.junit.jupiter:junit-jupiter-api:5.2.0")
    androidTestImplementation("de.mannodermaus.junit5:android-instrumentation-test:0.2.2")

    androidTestRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.2.0")
    androidTestRuntimeOnly("org.junit.platform:junit-platform-runner:1.2.0")
    androidTestRuntimeOnly("de.mannodermaus.junit5:android-instrumentation-test-runner:0.2.2")
    //androidTestImplementation("com.android.support.test:runner:1.0.2")
    //androidTestImplementation("com.android.support.test.espresso:espresso-core:3.0.2")
}