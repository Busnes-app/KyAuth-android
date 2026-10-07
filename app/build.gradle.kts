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
    compileSdk = 36

    defaultConfig {
        applicationId = "org.kysecurity.authenticator"
        minSdk = 31
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
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

dependencies {
    implementation("androidx.core:core-ktx:1.18.0")
    implementation("androidx.appcompat:appcompat:1.8.0")
    implementation("com.google.android.material:material:1.14.0")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.security:security-crypto:1.1.0")
    implementation("com.google.android.gms:play-services-code-scanner:16.1.0")
    implementation("com.google.firebase:firebase-messaging:25.1.2")
    implementation("app.keemobile:kotpass:0.13.0")
    implementation("com.google.guava:guava:33.7.1-android")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20231013")
    androidTestImplementation("androidx.test:core:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
}
