import java.util.Properties

plugins {
    java
}

val upstream = Properties().apply {
    file("../gradle.properties").inputStream().use { load(it) }
}
group = upstream.getProperty("group") + ".paper"
version = upstream.getProperty("version")
description = upstream.getProperty("description")

val paperApiVersion = "26.3.build.26-alpha"

repositories {
    mavenCentral()
    maven("https://repo.papermc.io/repository/maven-public/")
    maven("https://libraries.minecraft.net")
}

dependencies {
    compileOnly("io.papermc.paper:paper-api:$paperApiVersion")
    compileOnly("com.mojang:authlib:10.0.77")
    testImplementation(platform("org.junit:junit-bom:5.14.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("com.mojang:authlib:10.0.77")
    testImplementation("io.papermc.paper:paper-api:$paperApiVersion")
    testImplementation("com.google.code.gson:gson:2.13.2")
    testRuntimeOnly("com.h2database:h2:2.3.232")
}

java {
    toolchain.languageVersion = JavaLanguageVersion.of(25)
}

val generatedSources = layout.buildDirectory.dir("generated/sources/common/java")
val copyCommonSources by tasks.registering(Sync::class) {
    from("../common/src/main/java")
    into(generatedSources)
    filter { line: String ->
        line.replace("@version@", project.version.toString())
            .replace("@modrinthToken@", upstream.getProperty("modrinthID"))
            .replace("@loader@", "paper")
    }
}
sourceSets.main {
    java.srcDir(generatedSources)
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release = 25
}
tasks.compileJava {
    dependsOn(copyCommonSources)
}
tasks.processResources {
    from("../common/src/main/resources/templates/paper-plugin.yml") {
        expand(mapOf(
            "name" to "AlwaysAuth",
            "group" to project.group,
            "version" to project.version,
            "mainFile" to "AlwaysAuthPlugin",
            "description" to project.description,
            "apiVersion" to "26.3"
        ))
    }
}
tasks.jar {
    archiveBaseName = "AlwaysAuth-paper"
    destinationDirectory = layout.projectDirectory.dir("../build/all")
}
tasks.test {
    useJUnitPlatform()
}

tasks.register("verifyPaperApi") {
    group = "verification"
    description = "Assert the exact resolved Paper API used for the 26.3 artifact."
    doLast {
        val artifacts = configurations.compileClasspath.get().resolvedConfiguration.resolvedArtifacts
            .filter { it.moduleVersion.id.group == "io.papermc.paper" && it.name == "paper-api" }
        check(artifacts.size == 1 && artifacts.single().moduleVersion.id.version == paperApiVersion) {
            "Expected paper-api $paperApiVersion, got ${artifacts.map { it.moduleVersion.id }}"
        }
        println("io.papermc.paper:paper-api:jar:$paperApiVersion")
    }
}
tasks.check {
    dependsOn("verifyPaperApi")
}
