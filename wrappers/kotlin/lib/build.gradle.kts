/*
 * This file was generated by the Gradle 'init' task.
 *
 * This generated file contains a sample Kotlin library project to get you started.
 * For more details on building Java & JVM projects, please refer to https://docs.gradle.org/8.10.2/userguide/building_java_projects.html in the Gradle documentation.
 */

plugins {
    // Apply the org.jetbrains.kotlin.jvm Plugin to add support for Kotlin.
    alias(libs.plugins.kotlin.jvm)

    // Apply the java-library plugin for API and implementation separation.
    `java-library`

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

// Apply a specific Java toolchain to ease working on different environments.
java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

tasks.jar {
    manifest {
        attributes(
            "Bundle-NativeCode" to """
                org/devolutions/crypto/win32-x86-64/devolutions_crypto_uniffi.dll;osname=win32;processor=x86-64,
                org/devolutions/crypto/linux-x86-64/libdevolutions_crypto_uniffi.so;osname=linux;processor=x86-64,
                org/devolutions/crypto/linux-aarch64/libdevolutions_crypto_uniffi.so;osname=linux;processor=aarch64,
                org/devolutions/crypto/darwin-x86-64/libdevolutions_crypto_uniffi.dylib;osname=darwin;processor=x86-64,
                org/devolutions/crypto/darwin-aarch64/libdevolutions_crypto_uniffi.dylib;osname=darwin;processor=aarch64,
                org/devolutions/crypto/android-x86-64/libdevolutions_crypto_uniffi.so;osname=android;processor=x86-64,
                org/devolutions/crypto/android-armv7/libdevolutions_crypto_uniffi.so;osname=android;processor=armv7,
                org/devolutions/crypto/android-aarch64/libdevolutions_crypto_uniffi.so;osname=android;processor=aarch64,
                org/devolutions/crypto/android-x86/libdevolutions_crypto_uniffi.so;osname=android;processor=x86,
                com/sun/jna/android-aarch64/libjnidispatch.so;osname=android;processor=aarch64,
                com/sun/jna/android-armv7/libjnidispatch.so;osname=android;processor=armv7,
                com/sun/jna/android-x86/libjnidispatch.so;osname=android;processor=x86,
                com/sun/jna/android-x86-64/libjnidispatch.so;osname=android;processor=x86-64,
            """.trimIndent()
        )
    }
}

tasks.named<Test>("test") {
    // Use JUnit Platform for unit tests.
    useJUnitPlatform()


    // Configure test logging to display results in stdout
    testLogging {
        events("passed", "skipped", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        showStandardStreams = true
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
        create<MavenPublication>("maven") {
            groupId = "devolutions"
            artifactId = "devolutions-crypto"
            version = project.version.toString()
            from(components["java"])

            pom {
                name.set("Devolutions Crypto")
                description.set("Devolutions Cryptographic Library")
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
