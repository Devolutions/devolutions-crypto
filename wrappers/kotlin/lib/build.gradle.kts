plugins {
    // Apply the org.jetbrains.kotlin.jvm Plugin to add support for Kotlin.
    alias(libs.plugins.kotlin.jvm)

    // Apply the java-library plugin for API and implementation separation.
    `java-library`

    // Add the Maven Publish plugin to enable publishing artifacts.
    `maven-publish`
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
        languageVersion = JavaLanguageVersion.of(21)
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

// Configure the Maven Publish plugin to publish artifacts.
publishing {
    publications {
        // Create a Maven publication with metadata.
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            groupId = "com.devolutions"
            artifactId = "devolutions-crypto"
            version = "1.0.0" // Replace with your version

            // Add metadata for POM generation
            pom {
                name.set("Devolutions Crypto")
                description.set("Devolutions Cryptographic Library")
                url.set("https://github.com/Devolutions/devolutions-crypto")
                licenses {
                    license {
                        name.set("Apache-2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.html")
                    }
                }
                developers {
                    developer {
                        id.set("devolutions")
                        name.set("Devolutions")
                        email.set("ppare@devolutions.net")
                    }
                }
                scm {
                    connection.set("scm:git:git://github.com/Devolutions/devolutions-crypto.git")
                    developerConnection.set("scm:git:ssh://github.com:Devolutions/devolutions-crypto.git")
                    url.set("https://github.com/Devolutions/devolutions-crypto")
                }
            }
        }
    }

    repositories {}
}
