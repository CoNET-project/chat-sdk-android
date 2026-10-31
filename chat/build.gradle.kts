plugins {
    alias(libs.plugins.android.library)
    `maven-publish`
}

group = "network.conet"
version = "0.2.2"

android {
    namespace = "network.conet.chat"
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    // EncryptedSharedPreferences for the user PGP key + SI roster (never the EOA key).
    implementation(libs.androidx.security.crypto)

    testImplementation(libs.junit)
    // android.jar stubs org.json; unit tests need the real implementation.
    testImplementation(libs.org.json)
}

// Local Maven layout used by `scripts/publish-maven.sh` (consumed over raw.githubusercontent.com).
afterEvaluate {
    publishing {
        publications {
            register<MavenPublication>("release") {
                from(components["release"])
                groupId = "network.conet"
                artifactId = "chat"
                version = project.version.toString()
                pom {
                    name.set("CoNET Chat SDK for Android")
                    description.set(
                        "Native CoNET DePIN chat module (OpenPGP, mailbox listen, send, " +
                            "encrypted history) for Android hosts. WorkerCommand parity with " +
                            "@conet.project/chat-sdk.",
                    )
                    url.set("https://github.com/CoNET-project/chat-sdk-android")
                    licenses {
                        license {
                            name.set("MIT")
                            url.set("https://opensource.org/licenses/MIT")
                        }
                    }
                }
            }
        }
        repositories {
            maven {
                name = "repoMaven"
                url = uri(rootProject.layout.projectDirectory.dir("maven"))
            }
        }
    }
}
