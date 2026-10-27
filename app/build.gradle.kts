import java.util.Properties

plugins {
    id("com.android.application")
}

val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties().apply {
    if (keystorePropertiesFile.exists()) {
        keystorePropertiesFile.inputStream().use { load(it) }
    }
}

fun signingValue(env: String, property: String): String? =
    providers.environmentVariable(env).orNull
        ?: providers.gradleProperty(env).orNull
        ?: providers.gradleProperty(property).orNull
        ?: keystoreProperties[property] as String?

val signingMaterial: Map<String, String>? = run {
    val store = signingValue("KYAUTH_KEYSTORE", "storeFile")
    val storePassword = signingValue("KYAUTH_STORE_PASSWORD", "storePassword")
    val alias = signingValue("KYAUTH_KEY_ALIAS", "keyAlias")
    val keyPassword = signingValue("KYAUTH_KEY_PASSWORD", "keyPassword")
    if (store != null && storePassword != null && alias != null && keyPassword != null) {
        mapOf("storeFile" to store, "storePassword" to storePassword, "keyAlias" to alias, "keyPassword" to keyPassword)
    } else {
        null
    }
}

android {
    namespace = "org.kysecurity.authenticator"
    compileSdk = 37

    defaultConfig {
        applicationId = "org.kysecurity.authenticator"
        minSdk = 31
        targetSdk = 36
        versionCode = 6
        versionName = "0.5.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        buildConfigField("boolean", "ALLOW_SCREENSHOTS", "false")
    }

    signingConfigs {
        signingMaterial?.let { material ->
            create("release") {
                storeFile = file(material.getValue("storeFile"))
                storePassword = material.getValue("storePassword")
                keyAlias = material.getValue("keyAlias")
                keyPassword = material.getValue("keyPassword")
            }
        }
    }

    buildFeatures { buildConfig = true }

    // F-Droid rejects the Google-encrypted dependency block in an APK; Play reads it from the bundle.
    dependenciesInfo { includeInApk = false }

    // One applicationId for every channel: KyIdentity pins attestation to it, and the
    // org.kysecurity.identity account type can have only one owner on a device.
    flavorDimensions += "channel"
    productFlavors {
        create("play") {
            dimension = "channel"
            isDefault = true
            buildConfigField("boolean", "HAS_FCM", "true")
        }
        create("github") {
            dimension = "channel"
            buildConfigField("boolean", "HAS_FCM", "true")
        }
        // F-Droid ships no Google code: UnifiedPush only, zxing for QR.
        create("fdroid") {
            dimension = "channel"
            buildConfigField("boolean", "HAS_FCM", "false")
        }
    }

    sourceSets {
        // Explicit fixture builds only: public loopback anchors never enter release sources.
        providers.gradleProperty("tlsFixtureDir").orNull?.let { fixturePath ->
            val fixture = file(fixturePath)
            getByName("debug").manifest.srcFile(fixture.resolve("AndroidManifest.xml"))
            getByName("debug").res.srcDir(fixture.resolve("res"))
        }
        // Both: java.srcDir alone does not reach kotlinc for a flavor source set.
        listOf("play", "github").forEach { flavor ->
            getByName(flavor).java.srcDir("src/gms/java")
            getByName(flavor).kotlin.srcDir("src/gms/java")
            getByName(flavor).res.srcDir("src/gms/res")
            getByName(flavor).manifest.srcFile("src/gms/AndroidManifest.xml")
        }
    }

    buildTypes {
        debug {
            // Debug builds run in an emulator/IDE capture surface. Release remains secure by default.
            buildConfigField("boolean", "ALLOW_SCREENSHOTS", "true")
            val debugCert = providers.gradleProperty("kyauthDebugConsumerCert").orNull.orEmpty()
            require(debugCert.isEmpty() || Regex("[0-9a-f]{64}").matches(debugCert)) {
                "kyauthDebugConsumerCert must be 64 lowercase hex characters (SHA-256 of the DER signing certificate)"
            }
            buildConfigField("String", "DEBUG_CONSUMER_CERT", "\"$debugCert\"")
        }
        release {
            buildConfigField("String", "DEBUG_CONSUMER_CERT", "\"\"")
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (signingMaterial != null) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

// Google dependencies, named once and extended into play and github only.
val gmsImplementation by configurations.creating
configurations.named("playImplementation") { extendsFrom(gmsImplementation) }
configurations.named("githubImplementation") { extendsFrom(gmsImplementation) }

dependencies {
    implementation("androidx.core:core-ktx:1.19.1")
    implementation("androidx.appcompat:appcompat:1.8.0")
    implementation("com.google.android.material:material:1.14.0")
    implementation("androidx.biometric:biometric:1.1.0")
    gmsImplementation("com.google.android.gms:play-services-code-scanner:16.1.0")
    gmsImplementation("com.google.firebase:firebase-messaging:26.0.1")
    "fdroidImplementation"("com.journeyapps:zxing-android-embedded:4.3.0")
    implementation("org.unifiedpush.android:connector:3.3.5")
    // WebPush HKDF. Already shipped by the connector (runtime scope); same version, so no new code in the APK.
    implementation("com.google.crypto.tink:tink:1.24.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20260814")
    androidTestImplementation("androidx.test:core:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
}
