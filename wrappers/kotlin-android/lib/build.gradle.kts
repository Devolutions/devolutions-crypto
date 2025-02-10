/*
 * This file was generated by the Gradle 'init' task.
 *
 * This generated file contains a sample Kotlin library project to get you started.
 * For more details on building Java & JVM projects, please refer to https://docs.gradle.org/8.10.2/userguide/building_java_projects.html in the Gradle documentation.
 */

plugins {
    id("com.android.library") version "8.8.0"
    kotlin("android") version "2.1.10"

    id("maven-publish")
}

repositories {
    // Use Maven Central for resolving dependencies.
    mavenCentral()
}

dependencies {
    // Use the Kotlin JUnit 5 integration.
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")

    // Use the JUnit 5 integration.
    testImplementation(libs.junit.jupiter.engine)

    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    // This dependency is exported to consumers, that is to say found on their compile classpath.
    api(libs.commons.math3)

    // This dependency is used internally, and not exposed to consumers on their own compile classpath.
    implementation(libs.guava)
    implementation(libs.jna)
}

android {
    compileSdk = 34

    defaultConfig {
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    buildFeatures {
        viewBinding = true
    }
}

publishing {
    repositories {
        maven {
            name = "cloudsmith"
            url = uri("https://maven.cloudsmith.io/devolutions/maven-public/")
            credentials {
                username = System.getenv("CLOUDSMITH_USERNAME") ?: "bot-devolutions"
                password = System.getenv("CLOUDSMITH_API_KEY")
            }
        }
    }
    publications {
        create<MavenPublication>("mavenAndroid") {
            groupId = "devolutions"
            artifactId = "devolutions-crypto-android"
            version = project.version.toString()
            from(components["release"])

            pom {
                name.set("Devolutions Crypto (Android)")
                description.set("Devolutions Cryptographic Library for Android")
                url.set("https://github.com/devolutions/devolutions-crypto")

                licenses {
                    license {
                        name.set("Apache License 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.html")
                    }
                }
            }
        }
    }
}
