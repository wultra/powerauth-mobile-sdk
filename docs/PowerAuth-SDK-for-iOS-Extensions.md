# PowerAuth Mobile SDK for iOS and tvOS Extensions

<!-- begin remove -->
## Table of Contents

- [Installation](#installation)
   - [CocoaPods Installation](#cocoapods)
   - [Manual Installation](#manual)
- [SDK Configuration](#configuration)
   - [Prepare Data Sharing](#prepare-data-sharing)
   - [Configure PowerAuth for Extension](#configure-powerauth-for-extension)
- [Getting Device Activation Status](#getting-device-activation-status)
- [Token Based Authentication](#token-based-authentication)
   - [Getting token](#getting-token)
   - [Generating Authorization Header](#generating-authorization-header)
   - [Removing Token Locally](#removing-token-locally)
   - [Removing Token From the Server](#removing-tokenf-from-the-server)
- [Common SDK Tasks](#common-sdk-tasks)
- [Troubleshooting](#troubleshooting)

Related documents:

- [PowerAuth SDK for iOS](./PowerAuth-SDK-for-iOS.md)
- [PowerAuth SDK for watchOS](./PowerAuth-SDK-for-watchOS.md)
<!-- end -->

## Installation

This chapter describes how to get PowerAuth SDK for iOS and tvOS Extensions up and running in your app. In current version, you can choose between CocoaPods and manual library integration. Both types of installation will lead to your app extension linked with a dynamic library, provided by the `PowerAuth2ForExtensions.[xc]framework`.

To distinguish between SDKs, the following short terms will be used in this document:

- **iOS SDK**, as short term for *PowerAuth SDK for iOS and tvOS*
- **Extensions SDK** as short term for *PowerAuth SDK for iOS and tvOS Extensions*

### CocoaPods

[CocoaPods](http://cocoapods.org) is a dependency manager for Cocoa projects. You can install it with the following command:
```bash
$ gem install cocoapods
```

To integrate PowerAuth library into your Xcode project using CocoaPods, specify it in your `Podfile`:
```ruby
platform :ios, '9.0'

target 'YourAppTarget' do
  pod 'PowerAuth2'
end

target 'YourExtensionTarget' do
  pod 'PowerAuth2ForExtensions'
end
```

Then, run the following command:
```bash
$ pod install
```

### Manual

If you prefer not to use CocoaPods as dependency manager, you can integrate Extensions SDK into your project manually as a git [submodule](http://git-scm.com/docs/git-submodule).

#### Git Submodules

The integration process is quite similar to integration of our IOS library:

1. Open up Terminal.app and go to your top-level project directory and add the library as a submodule:
    ```sh
    $ git submodule add https://github.com/wultra/powerauth-mobile-sdk.git PowerAuthLib
    $ git submodule update --init --recursive
    ```
    First command will clone PowerAuth SDK into `PowerAuthLib` folder and second, will update all nested submodules. We're expecting that you already did this when you integrated PowerAuth into your application.

2. Open the new `PowerAuthLib` folder, and go to `proj-xcode` sub-folder
3. Drag the `PowerAuthExtensionSdk.xcodeproj` project file into **Project Navigator** of your application's Xcode project. It should appear nested underneath your application's blue project icon.
4. Select your application project in the Project Navigator to navigate to the target configuration window and select the extension's target under the **TARGETS** heading in the sidebar.
5. Now select **Build Phases** tab and expand **Target Dependencies** section. Click on the "Plus Sign" and choose **"PowerAuth2ForExtensions"** framework from the **"PowerAuthExtensionSdk"** project.
6. Next, in the same **Build Phases** tab expand **Link With Libraries** section. Click on the "Plus Sign" and choose **"PowerAuth2ForExtensions.framework"** from the **"PowerAuthExtensionSdk"** project.



## Configuration

The Extensions SDK shares several source codes and configuration principles with main iOS SDK. So, you can prepare the same set of constants as you're already using in your IOS application. The SDK provides just a limited functionality for app extension (for example, you cannot create an activation or calculate a full PowerAuth signature from an extension) and to do that it requires access to an activation data, created in the main application.

### Prepare Data Sharing

The App Extension normally doesn't have an access to data created by the main application, so the first step is to setup a data sharing for your project.

#### Keychain Sharing

iOS SDK is storing its most sensitive data into the iOS keychain, so you need to configure the keychain sharing first. If you're not familiar with keychain sharing, then don't worry about that, the keychain is shared only between the vendor's applications. So the sensitive information is not exposed to 3rd party applications.

1. Select your application project in the **Project Navigator** to navigate to the target configuration window and select the applications's target under the **TARGETS** heading in the sidebar.
2. Now select **Capabilities** tab and expand **Keychain Sharing** section.
3. Turn "ON" **Keychain Sharing** and Xcode will predefine first **Keychain Group** to your application's bundle name. Let's call this value as `KEYCHAIN_GROUP_NAME`

<!-- begin box info -->
The predefined group is usually beneficial, because iOS is by default using that group for storing all keychain entries created in the application. So, If your application is already using PowerAuth and you're going to just add a support for extension, then this is the most simple way to setup a keychain sharing.
<!-- end -->

Now you have to do a similar setup for your application's extension:

4. Select your application project in the **Project Navigator** to navigate to the target configuration window and select the extensions's target under the **TARGETS** heading in the sidebar.
5. Select **Capabilities** tab and expand **Keychain Sharing** section.
6. Turn "ON" **Keychain Sharing** and set the same `KEYCHAIN_GROUP_NAME` as you did for the application's target.
7. (optional) Repeat steps 4 to 6 for all other extensions which suppose to use Extensions SDK.

Now you need to know your **Team ID** (the unique identifier assigned to your team by Apple). Unfortunately, the identifier is not simply visible in Xcode, sou you'll have to log in into the Apple's [development portal](http://developer.apple.com) and look for that identifier in your membership details page.

If you know the Team ID, then the final `KEYCHAIN_GROUP_IDENTIFIER` constant is composed as `TEAM_ID.KEYCHAIN_GROUP_NAME`. So, it should look like: `KTT00000MR.com.powerauth.demo.App`.

#### App Groups

The PowerAuth SDK for iOS is using one boolean flag stored in the `UserDefaults` facility, to determine whether the application has been reinstalled. Unfortunately, `UserDefaults.standard` created by the application cannot be shared with the app extension, so you have to create a new application group to share that data.

1. Select your application project in the **Project Navigator** to navigate to the target configuration window and select the applications's target under the **TARGETS** heading in the sidebar.
2. Now select **Capabilities** tab and expand **App Groups** section.
3. Turn "ON" **App Groups** and add group with desired identifier and turn this particular group ON (e.g. make sure that checkmark close to group's name is selected). Let's call this value as `APP_GROUP_IDENTIFIER`.
4. Now switch to application's extension target, select **Capabilities** tab and also expand **App Groups** section.
5. Turn "ON" **App Groups** for extension and add app group with the same name as you did in step 3.

You can optionally check a troubleshooting section if you need to [migrate the keychain initialization flag](#userdefaults-migration) from standard user defaults to a shared one.

<!-- begin box info -->
While all previous steps are optional, they are highly recommended. If the keychain is properly shared, then the Extension SDK can determine the status of the PowerAuth activation just from the content of keychain data. But still this has a drawback, because the keychain data persists between the application's reinstallation. As you can see, in couple of rare usage scenarios the extension may get an inaccurate information about the activation.
<!-- end -->

### Configure PowerAuth for Extension

If the data sharing is right, then the configuration of PowerAuth SDK for iOS Extension is pretty straightforward:

```swift
import PowerAuth2ForExtensions

class TodayViewController: UIViewController, NCWidgetProviding {

    // Lazy initialized variable
    private var powerAuthExt: PowerAuthExtensionSDK = {
        return TodayViewController.setupPowerAuth()
    }()

    private static func setupPowerAuth() -> PowerAuthExtensionSDK {
        let config = PowerAuthConfiguration()
        config.instanceId = "your-app-bundle-name";
        config.appKey = "sbG8gd...MTIzNA=="
        config.appSecret = "aGVsbG...MTIzNA=="
        config.masterServerPublicKey = "MTIzNDU2Nz...jc4OTAxMg=="
        // URL is optional, current version of Extensions SDK doesn't perform own networking.
        config.baseEndpointUrl = "https://localhost:8080/demo-server"

        let keychainConfig = PA2KeychainConfiguration.sharedInstance()
        keychainConfig.keychainAttribute_AccessGroup = "KEYCHAIN_GROUP_IDENTIFIER"
        keychainConfig.keychainAttribute_UserDefaultsSuiteName = "APP_GROUP_IDENTIFIER"

        return PowerAuthExtensionSDK(configuration: config, keychainConfiguration: keychainConfig)!
    }

    // ... the rest of the controller's code ...
}
```

<!-- begin box warning -->
**IMPORTANT:** The configuration used above must match configuration used in the application otherwise your extension will never get a proper activation status.
<!-- end -->

The Extensions SDK doesn't provide a shared instance for `PowerAuthExtensionSDK` class and therefore you have to manage that instance on your own. The example above shows a beginning of simple controller implementing extension for Today Widget. For all other code examples, we're going to use `this.powerAuthExt` as properly initialized instance of `PowerAuthExtensionSDK` object.


## Getting Device Activation Status

Unlike the iOS SDK, the Extension SDK provides only a limited information about activation status. You can actually check only whether there's locally stored activation or not:

```swift
if this.powerAuthExt.hasValidActivation() {
    // main application has a valid activation locally stored
}
```


## Token Based Authentication

<!-- begin box warning -->
**WARNING:** Before you start using access tokens, please visit our [wiki page for powerauth-crypto](https://github.com/wultra/powerauth-crypto/blob/develop/docs/MAC-Token-Based-Authentication.md) for more information about this feature. You can also check documentation about tokens available in [PowerAuth SDK for iOS](./PowerAuth-SDK-for-iOS.md#token-based-authentication).
<!-- end -->


### Getting Token

To get an access token, you can use following code:

```swift
if let token = this.powerAuthExt.tokenStore.localToken(withName: "MyToken") {
    // you have a token which can generate authorization headers
}
```

Note that token store also provides `requestAccessToken()` method, but that always returns `PA2ErrorCodeInvalidToken` error. Unlike the iOS SDK API, you cannot get a token from the server from app extension. Only main application can do that and once the token is available, then it's also available for the app extension. Check PowerAuth SDK for iOS [documentation for more details](./PowerAuth-SDK-for-iOS.md#getting-token).

### Generating Authorization Header

Once you have a `PowerAuthToken` object, use following code to generate an authorization header:

```swift
if let header = token.generateHeader() {
    let httpHeader = [ header.key : header.value ]
    // now you can attach that httpHeader to your HTTP request
} else {
    // in case of nil, token is no longer valid
}
```

### Removing Token Locally

To remove token locally, you can simply use following code:

```swift
let tokenStore = this.powerAuthExt.tokenStore
// Remove just one token
tokenStore.removeLocalToken(withName: "MyToken")
// Remove all local tokens
tokenStore.removeAllLocalTokens()
```

Note that removing tokens locally you'll loose control about tokens stored on the server. This is the same situation as in application.

### Removing Token From the Server

The token store exposes `removeAccessToken()` method, but the implementation always returns `PA2ErrorCodeInvalidToken` error.

## Common SDK Tasks

### Error Handling

You can follow the same practices as for iOS SDK because Extensions SDK codebase is sharing the same error constants with a full PowerAuth SDK for iOS.

### Debug Build Detection

It is sometimes useful to switch Extensions SDK to a DEBUG build configuration, to get more logs from the library:

- **CocoaPods:** we currently don't provide DEBUG pod. This will be resolved in some future versions of Extensions SDK.
- **Manual installation:** Xcode is matching build configuration across all nested projects, so you usually don't need to care about the configuration switching.

The DEBUG build is usually helpful during the application development, but on other side, it's highly unwanted in production applications. For this purpose, the `PA2ExtensionLibrary.isInDebug()` method provides an information, whether the PowerAuth for Extensions library was compiled in DEBUG configuration. It is a good practice to check this flag and crash the process when the production application is linked against the DEBUG library:

```swift
#if YOUR_APPSTORE_BUILD_FLAG
    // Final vs Debug library trap
    if PA2ExtensionLibrary.isInDebug() {
        fatalError("CRITICAL ERROR: You're using Debug PowerAuth library in production build.")
    }
#endif
```

## Troubleshooting

This section of document contains a various workarounds and tips for Extensions SDK usage.

### UserDefaults Migration

If your previous version of application did not use shared data between application and the extension, then you probably need to migrate keychain status flag from `UserDefaults.standard` to shared one. We recommend to perform this migration at the main application's startup code and **BEFORE** the `PowerAuthSDK` object is configured and used:

```swift
private func migrateUserDefaults() {
    let keychainConfig = PA2KeychainConfiguration.sharedInstance()
    let suiteName = keychainConfig.keychainAttribute_UserDefaultsSuiteName
    guard let shared = UserDefaults(suiteName: suiteName) else {
        return // data sharing is probably not configured properly
    }
    if shared.bool(forKey: PA2Keychain_Initialized) {
        return // migration is not required
    }
    let standard = UserDefaults.standard
    if standard.bool(forKey: PA2Keychain_Initialized) {
        standard.removeObject(forKey: PA2Keychain_Initialized)
        standard.synchronize()
        shared.set(true, forKey: PA2Keychain_Initialized)
        shared.synchronize()
    }
}
```
