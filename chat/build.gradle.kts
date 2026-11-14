plugins {
    alias(libs.plugins.android.library)
    `maven-publish`
}

group = "network.conet"
version = "0.2.16"

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
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // ChatDaemon protocol v1 shared vectors (copy of the spec's file, see
    // scripts/sync-protocol-vectors.sh): JVM tests read them as a resource,
    // instrumented tests as an asset.
    sourceSets {
        getByName("test").resources.srcDir(rootProject.file("spec"))
        getByName("androidTest").assets.srcDir(rootProject.file("spec"))
        // P-IMP-PGP option A acceptance harness and adapters (spec r3l §25.30.8): one copy for the JVM and the device tests.
        getByName("test").kotlin.srcDir("src/sharedAcceptance/java")
        getByName("androidTest").kotlin.srcDir("src/sharedAcceptance/java")
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

    // bcprov, bcpg and bcutil 1.87 each carry META-INF/LICENSE.md, and the three copies are byte-identical (the BouncyCastle
    // licence). Only this one path is resolved (first copy kept), so the instrumented test APK can be merged and the licence
    // text stays in it. Other META-INF files keep the default duplicate check.
    packaging {
        resources {
            pickFirsts += setOf("META-INF/LICENSE.md")
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    // BouncyCastle 1.87 (latest formal release; OSV: no known vulnerabilities for 1.85.2+, 1.84 has two):
    // native secp256k1 signing and OpenPGP sign / decrypt only.
    implementation("org.bouncycastle:bcprov-jdk18on:1.87")
    implementation("org.bouncycastle:bcpg-jdk18on:1.87")
    // EncryptedSharedPreferences for the user PGP key + SI roster (never the EOA key).
    implementation(libs.androidx.security.crypto)

    testImplementation(libs.junit)
    // SQLite JVM driver for store tests only (xerial sqlite-jdbc 3.54.1.0, Apache-2.0; OSV: no advisories).
    testImplementation("org.xerial:sqlite-jdbc:3.54.1.0")
    // android.jar stubs org.json; unit tests need the real implementation.
    testImplementation(libs.org.json)

    androidTestImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.runner)
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
