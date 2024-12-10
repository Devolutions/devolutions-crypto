import java.util.Properties

// Top-level build file where you can add configuration options common to all sub-projects/modules.

buildscript {
    repositories {
        google()
        jcenter() // Note: jcenter is deprecated, consider using Maven Central
    }
    dependencies {
        classpath("com.android.tools.build:gradle:4.1.3")
    }
}

allprojects {
    apply(plugin = "maven-publish")

    repositories {
        google()
        jcenter() // Replace with mavenCentral() if possible
    }
}

val properties = Properties().apply {
    load(project.rootProject.file("local.properties").inputStream())
}

project(":devolutions-crypto") {
    extra["libraryVersion"] = "1.0.0" // Replace with your desired version

    publishing {
        repositories {
            maven {
                name = "cloudsmith"
                url = uri("https://maven.cloudsmith.io/devolutions/maven-public/")
                credentials {
                    username = System.getenv("CLOUDSMITH_USERNAME") ?: ""
                    password = System.getenv("CLOUDSMITH_API_KEY") ?: ""
                }
            }
        }
        publications {
            create<MavenPublication>("aar") {
                groupId = "com.devolutions"
                artifactId = project.name
                version = extra["libraryVersion"] as String
                // Use the .aar file if applicable; adjust if you are generating .jar instead
                artifact("$buildDir/outputs/aar/${project.name}-release.aar")
            }
        }
    }
}

tasks.register("clean", Delete::class) {
    delete(rootProject.buildDir)
}
