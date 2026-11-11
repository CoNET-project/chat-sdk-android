pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // Authorized (user, 2026-11-11): repo1 only, for these two groups.
        maven {
            url = uri("https://repo1.maven.org/maven2/")
            content {
                includeGroup("org.bouncycastle")
                includeGroup("org.xerial")
            }
        }
    }
}

rootProject.name = "chat-sdk-android"
include(":chat")
