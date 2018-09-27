// Top-level build file where you can add configuration options common to all sub-projects/modules.

buildscript {
    repositories {
        google()
        jcenter()
    }

    dependencies {
        classpath("com.android.tools.build:gradle:3.2.0")
        classpath(kotlin("gradle-plugin", version = "1.2.71"))
        //classpath("de.mannodermaus.gradle.plugins:android-junit5:1.2.0.0")
    }
}

allprojects {
    repositories {
        google()
        jcenter()
        maven(url = "https://dl.bintray.com/terl/lazysodium-maven")
    }
}

tasks.register("clean", Delete::class) {
    delete(rootProject.buildDir)
}