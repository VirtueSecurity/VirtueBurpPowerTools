plugins {
    // Provides Kotlin Language Support
    // https://plugins.gradle.org/plugin/org.jetbrains.kotlin.jvm
    kotlin("jvm") version "2.3.0"

    // Provides the shadowJar task in Gradle
    // https://plugins.gradle.org/plugin/com.github.johnrengelman.shadow
    id("com.github.johnrengelman.shadow") version "8.1.1"

}

//Change this to reflect your package namespace
group = "com.virtuesecurity.montoya"
version = "0.1.0"

repositories {
    //add maven local in case you want to build some reusable libraries and host them within your home directory
    mavenLocal()
    mavenCentral()


    maven(url="https://jitpack.io") {
        content {
            includeGroup("com.github.ncoblentz")
        }
    }

}

dependencies {
    //testImplementation(kotlin("test"))

    // Include the Montoya API from Maven Central:
    // https://central.sonatype.com/artifact/net.portswigger.burp.extensions/montoya-api
    // Check for latest version: https://central.sonatype.com/artifact/net.portswigger.burp.extensions/montoya-api/versions
    implementation("net.portswigger.burp.extensions:montoya-api:2025.12")

    // Enable these if you want to use https://github.com/ncoblentz/BurpMontoyaLibrary
    implementation("com.github.ncoblentz:BurpMontoyaLibrary:0.2.0")

    implementation("org.json:json:20250517")

    implementation("org.apache.commons:commons-text:1.15.0")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-swing:1.10.2")
    implementation("io.ktor:ktor-client-core:3.4.0")
    implementation("io.ktor:ktor-client-cio:3.4.0")

    implementation("at.yawk.lz4:lz4-java:1.10.3")

}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(25)
}