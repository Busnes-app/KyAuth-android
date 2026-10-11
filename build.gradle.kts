buildscript {
    // AGP 9.4.1 still resolves these onto the build classpath at releases with published
    // advisories. Build tooling only; none of them ships in the APK. Raise, never pin down.
    dependencies {
        constraints {
            classpath("org.bouncycastle:bcprov-jdk18on:1.86")
            classpath("org.bouncycastle:bcpkix-jdk18on:1.86")
            classpath("org.bouncycastle:bcutil-jdk18on:1.86")
            classpath("org.bitbucket.b_c:jose4j:0.9.7")
            classpath("org.jdom:jdom2:2.0.6.1")
        }
    }
}

plugins {
    id("com.android.application") version "9.4.1" apply false
}
