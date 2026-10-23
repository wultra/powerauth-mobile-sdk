# SDK Installation

To get PowerAuth SDK for Android up and running in your app, add the following dependency in your `gradle.build` file:

```gradle
repositories {
    mavenCentral() // if not defined elsewhere...
}

dependencies {
    implementation 'com.wultra.android.powerauth:powerauth-sdk:2.x.y'
}
```

Note that this documentation is using version `2.x.y` as an example. You can find the latest version in our [List of Releases](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Releases.md). The Android Studio IDE can also find and offer updates for your application's dependencies.

From now on, you can use `PowerAuthSDK` class in your project.

To use development version, you need to install it in your local Maven repository and make this repository available to your Gradle script.

```sh
$ git clone --recurse-submodules https://github.com/wultra/powerauth-mobile-sdk.git
$ cd powerauth-mobile-sdk/proj-android
$ sh build-publish-local.sh
```

In your Gradle script:

```gradle
apply plugin: "maven"

repositories {
    mavenLocal()
}
```

You also need to install base Java modules in your maven repository:

```sh
$ git clone --recurse-submodules https://github.com/wultra/powerauth-restful-integration.git
$ cd powerauth-restful-integration
$ mvn clean install -DskipTests=true
```

## Read Next

- [SDK Configuration](Android-Configuration.md)
