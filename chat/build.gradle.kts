plugins {
    alias(libs.plugins.android.library)
    `maven-publish`
}

group = "network.conet"
version = "0.2.22-rc2.1-diag4"

android {
    namespace = "network.conet.chat"
    buildFeatures {
        buildConfig = true
    }
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        minSdk = 24
        // QA switch (R559): -PchatDisableHistoryWrites=true builds a candidate whose history writes nothing (no fragment, index or
        // pointer upload). Without the property the value is true, as before: production behaviour does not change.
        // Only the value "true" switches writes off: -PchatDisableHistoryWrites=false (or any other value) keeps them on (R565 review).
        buildConfigField(
            "boolean",
            "HISTORY_WRITES",
            (project.findProperty("chatDisableHistoryWrites")?.toString() != "true").toString(),
        )
        // QA-only capability (spec 25.52Y.44, PM R2042): the SDK declares wallet.credential.v1 only in a QA candidate built with
        // -PchatWalletCredentialQa=true. Without the property the bit is not declared (production unchanged).
        buildConfigField(
            "boolean",
            "WALLET_CREDENTIAL_QA",
            (project.findProperty("chatWalletCredentialQa")?.toString() == "true").toString(),
        )
        // QA-only capability (identity.native-keys.v1, PM ruling for the 0.2.22-rc1 device candidate): declared only in a QA candidate built
        // with -PchatNativeKeysQa=true. Without the property the bit is not declared; the formal build is not declared until the gate passes.
        buildConfigField(
            "boolean",
            "NATIVE_KEYS_QA",
            (project.findProperty("chatNativeKeysQa")?.toString() == "true").toString(),
        )
        // The artifact version as a build constant (spec 25.52Y.45, PM R2054): the SDK reports it as hello.sdkVersion; a test compares them.
        buildConfigField("String", "VERSION_NAME", "\"${project.version}\"")
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

    // QA-only hooks (spec r3bw §25.52AA.5): compiled only when the QA build asks for them with -PchatQaHooks. The production AAR never
    // contains them: the hook sources live in src/qa/java and their behaviour tests in src/qaTest/java, and neither is added otherwise.
    if (project.hasProperty("chatQaHooks")) {
        sourceSets {
            getByName("main").kotlin.srcDir("src/qa/java")
            getByName("test").kotlin.srcDir("src/qaTest/java")
        }
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

// The QA hook presence test reads the property in the test JVM (HK-01, HK-02).
tasks.withType<org.gradle.api.tasks.testing.Test>().configureEach {
    if (project.hasProperty("chatQaHooks")) systemProperty("chatQaHooks", "true")
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
