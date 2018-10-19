import org.jetbrains.kotlin.config.KotlinCompilerVersion
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
//import de.mannodermaus.gradle.plugins.junit5.*

plugins {
    id("com.android.library")
    id("kotlin-android")
    id("com.github.dcendents.android-maven")
    id("org.jetbrains.dokka-android") version "0.9.17"
}

val group: String = "com.ncryptf"

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

android {
    compileSdkVersion(28)
    defaultConfig {
        minSdkVersion(19)
        targetSdkVersion(28)
        versionCode = 1
        versionName = "0.2.0"
        multiDexEnabled = true
        testInstrumentationRunner = "android.support.test.runner.AndroidJUnitRunner"
        testInstrumentationRunnerArgument("NCRYPTF_TEST_API", System.getenv("NCRYPTF_TEST_API") ?: "_")
        testInstrumentationRunnerArgument("ACCESS_TOKEN", System.getenv("ACCESS_TOKEN") ?: "_")
        //testInstrumentationRunnerArgument("runnerBuilder", "de.mannodermaus.junit5.AndroidJUnit5Builder")
    }

    dexOptions {
        preDexLibraries = false
        dexInProcess = false
    }

    lintOptions {
        isAbortOnError = false
        textReport = true
        textOutput("stdout")
        isCheckAllWarnings = true
        isWarningsAsErrors = true
        isCheckReleaseBuilds = false
        isCheckTestSources = true
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android.txt"), "proguard-rules.pro")
        }

        getByName("debug") {
           proguardFiles(getDefaultProguardFile("proguard-android.txt"), "proguard-rules.pro")
           multiDexKeepProguard = file("proguard-multidex-rules.pro")
        }
    }

    sourceSets {
        getByName("androidTest").java.srcDirs("src/androidTest/kotlin")
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
        exclude("app/src/androidTest/**")
    }

    testOptions {
        unitTests.apply {
            isReturnDefaultValues = true
            isIncludeAndroidResources = false
        }
    }
}

val dokka by tasks.getting(org.jetbrains.dokka.gradle.DokkaAndroidTask::class) {
    outputFormat = "html"
    outputDirectory = "$buildDir/javadoc"
    jdkVersion = 8
    reportUndocumented = true
    skipEmptyPackages = true
    noStdlibLink = false
    skipDeprecated = false
}

val version = KotlinCompilerVersion.VERSION
println("Kotlin Version: " + version)

dependencies {
    implementation(kotlin("stdlib-jdk8", KotlinCompilerVersion.VERSION))

    implementation("com.goterl.lazycode:lazysodium-android:3.3.0@aar")
    implementation("net.java.dev.jna:jna:4.5.2@aar")

    implementation("at.favre.lib:hkdf:1.0.0")
    implementation("commons-codec:commons-codec:1.11:@jar")

    // for java.time.* classes
    implementation("com.jakewharton.threetenabp:threetenabp:1.1.1")

    testImplementation("junit:junit:4.12")

    androidTestImplementation("com.squareup.okio:okio:2.1.0@jar")
    androidTestImplementation("com.squareup.okhttp3:okhttp:3.11.0@jar")

    androidTestImplementation("com.android.support.test:runner:1.0.2")
    androidTestImplementation("com.android.support.test:rules:1.0.2")

    androidTestImplementation("com.android.support.test.espresso:espresso-core:3.0.2")

    //testImplementation("org.junit.jupiter:junit-jupiter-api:5.2.0")
    //testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.2.0")
    //testImplementation("org.junit.jupiter:junit-jupiter-params:5.2.0")

    //androidTestImplementation("org.junit.jupiter:junit-jupiter-api:5.2.0")
    //androidTestImplementation("de.mannodermaus.junit5:android-instrumentation-test:0.2.2")

    //androidTestRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.2.0")
    //androidTestRuntimeOnly("org.junit.platform:junit-platform-runner:1.2.0")
    //androidTestRuntimeOnly("de.mannodermaus.junit5:android-instrumentation-test-runner:0.2.2")
}