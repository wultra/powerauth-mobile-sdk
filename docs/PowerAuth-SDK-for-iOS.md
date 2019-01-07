---
layout: page
title: PowerAuth Mobile SDK for iOS Apps
---

## Table of Contents

- [Installation](#installation)
   - [CocoaPods Installation](#cocoapods)
   - [Manual Installation](#manual)
   - [Carthage Installation](#carthage)
- [Post-Installation steps](#post-installation-steps)
   - [Disabling bitcode](#disabling-bitcode)
   - [Include PowerAuth SDK in your sources](#include-powerauth-sdk-in-your-sources)
- [SDK Configuration](#configuration)
- [Device Activation](#activation)
- [Requesting Device Activation Status](#requesting-activation-status)
- [Data Signing](#data-signing)
   - [Symmetric Multi-Factor Signature](#symmetric-multi-factor-signature)
   - [Asymmetric Private Key Signature](#asymmetric-private-key-signature)
   - [Symmetric Offline Multi-Factor Signature](#symmetric-offline-multi-factor-signature)
   - [Verify server signed data](#verify-server-signed-data)
- [Password Change](#password-change)
- [Biometry Setup](#biometry-setup)
- [Device Activation Removal](#activation-removal)
- [End-To-End Encryption](#end-to-end-encryption)
- [Secure Vault](#secure-vault)
- [Token Based Authentication](#token-based-authentication)
- [Apple Watch Support](#apple-watch-support)
   - [Prepare Watch Connectivity](#prepare-watch-connectivity)
   - [WCSession activation sequence](#wcsession-activation-sequence)
   - [Sending Activation Status to Watch](#sending-activation-status-to-watch)
   - [Sending Token to Watch](#sending-token-to-watch)
   - [Removing Token from Watch](#removing-token-from-watch)
- [Common SDK Tasks](#common-sdk-tasks)
- [Additional Features](#additional-features)

Related documents:

- [PowerAuth SDK for iOS App Extensions](./PowerAuth-SDK-for-iOS-Extensions)
- [PowerAuth SDK for watchOS](./PowerAuth-SDK-for-watchOS)


## Installation

This chapter describes how to get PowerAuth SDK for iOS up and running in your app. In current version, you can choose between CocoaPods and manual library integration.

### CocoaPods

[CocoaPods](http://cocoapods.org) is a dependency manager for Cocoa projects. You can install it with the following command:
```bash
$ gem install cocoapods
```

To integrate PowerAuth library into your Xcode project using CocoaPods, specify it in your `Podfile`:
```ruby
platform :ios, '8.0'
target '<Your Target App>' do
  pod 'PowerAuth2'
end

# Disable bitcode for iOS targets (also see chapter Disabling bitcode)
post_install do |installer|
  installer.pods_project.targets.each do |target|
    if target.platform_name == :ios
      puts "Disabling bitcode for target  #{target.name}"
      target.build_configurations.each do |config|
        config.build_settings['ENABLE_BITCODE'] = 'NO'
      end
    end
  end
end
```

Then, run the following command:
```bash
$ pod install
```

### Manual

If you prefer not to use CocoaPods as dependency manager, you can integrate PowerAuth into your project manually as a git [submodule](http://git-scm.com/docs/git-submodule).

#### Git submodules

1. Open up Terminal.app and go to your top-level project directory and add the library as a submodule:
    ```sh
    $ git submodule add https://github.com/wultra/powerauth-mobile-sdk.git PowerAuthLib
    $ git submodule update --init --recursive
    ```
    First command will clone PowerAuth SDK into `PowerAuthLib` folder and second, will update all nested submodules.

2. Open the new `PowerAuthLib` folder, and go to `proj-xcode` sub-folder
3. Drag the `PowerAuthLib.xcodeproj` project file into **Project Navigator** of your application's Xcode project. It should appear nested underneath your application's blue project icon.
4. Select your application project in the Project Navigator to navigate to the target configuration window and select the extension's target under the **TARGETS** heading in the sidebar.
5. Now select **Build Phases** tab and expand **Target Dependencies** section. Click on the "Plus Sign" and choose **"PowerAuth2"** framework from the **"PowerAuthLib"** project.
6. Next, in the same **Build Phases** tab expand **Link With Libraries** section. Click on the "Plus Sign" and choose **"PowerAuth2.framework"** from the **"PowerAuthLib"** project.

### Carthage

We provide a limited and experimental support for [Carthage dependency manager](https://github.com/Carthage/Carthage). The current problem with Carthage is that we cannot specify which Xcode project and which Scheme has to be used for particular library build. It kind of works automatically, but the build process is extremely slow and not reliable. So, if you still want to try integrate our library with Carghate, try following tips:

- Add `github "wultra/powerauth-mobile-sdk" "feature/carthage-build"` into your `Cartfile`. We're maintaining separate branch for Carthage builds, so if it's not up to date, please let us know. We'll update that branch as soon as possible.
- It's recommended to force Carthage to use submodules for library code checkouts.
- It's recommended to update only iOS platform (if possible). So try to run something like this: `carthage update --use-submodules --platform ios`


## Post-installation steps

Following steps are recommended for all types of installations.

### Disabling Bitcode

When the `Enable Bitcode` option is set to `YES`, your application is build to LLVM IR (intermediate representation) rather than to the final executable binary. Later, the final binary is built in the Apple cloud for various architectures. As a result of this process, you are not in control of what actually goes in your binary. Any application with high security requirements cannot accept this proposition. As a result, PowerAuth SDK for iOS cannot be built with `Enable Bitcode` option enabled.

To disable Bitcode, go to your project `Build Settings`, search for `Enable Bitcode` option and set value to `NO`.

![Disable Bitcode in Xcode](https://github.com/wultra/powerauth-mobile-sdk/wiki/images/ios_manual_04_bitcode.png)

### Include PowerAuth SDK in your sources

To use PowerAuth SDK, simply add following imports into your code:

```swift
// swift
import PowerAuth2
```

```objc
// Objective-C
#import <PowerAuth2/PowerAuth2.h>
```

From now on, you can use `PowerAuthSDK` and other classes in your project.

## Configuration

In order to be able to configure your `PowerAuthSDK` instance, you need following values from the PowerAuth 2.0 Server:

- `APP_KEY` - Application key, that binds activation with specific application.
- `APP_SECRET` - Application secret, that binds activation with specific application.
- `KEY_MASTER_SERVER_PUBLIC` - Master Server Public Key, used for non-personalized encryption and server signature verification.

Also, you need to specify your instance ID (by default, this can be for example an app bundle ID). This is because one application may use more than one custom instances of `PowerAuthSDK` and identifier is the way to distinguish these instances while working with Keychain data.

Finally, you need to know the location of your [PowerAuth 2.0 Standard RESTful API](https://github.com/wultra/powerauth-crypto/wiki/Standard-RESTful-API) endpoints. Tha path should contain everything that goes before the `/pa/**` prefix of the API endpoints.

To sum it up, in order to configure `PowerAuthSDK` default instance, add following code to your application delegate:

```swift
func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplicationLaunchOptionsKey: Any]?) -> Bool {

    // Prepare the configuration
    let configuration = PowerAuthConfiguration()
    configuration.instanceId = Bundle.main.bundleIdentifier ?? ""
    configuration.appKey = "sbG8gd...MTIzNA=="
    configuration.appSecret = "aGVsbG...MTIzNA=="
    configuration.masterServerPublicKey = "MTIzNDU2Nz...jc4OTAxMg=="
    configuration.baseEndpointUrl = "https://localhost:8080/demo-server"

    // Configure default PowerAuthSDK instance
    PowerAuthSDK.initSharedInstance(configuration)

    return true
}
```

## Activation

After you configure the SDK instance, you are ready to make your first activation.

### Activation via Activation Code

The original activation method uses a one-time activation code generated in PowerAuth 2.0 Server. To create an activation using this method, some external application (Internet banking, ATM application, branch / kiosk application) must generate an activation code for you and display it (as a text or in a QR code).

Use following code to create an activation once you have an activation code:

```swift
// Call reset to clear any pending activation data from previous attempts
PowerAuthSDK.sharedInstance().reset()

let deviceName = "Petr's iPhone 7" // or UIDevice.current.name
let activationCode = "12345-67890-12345-67890" // let user type or QR-scan this value

// Create a new activation with given device name and activation code
PowerAuthSDK.sharedInstance().createActivation(withName: deviceName, activationCode: activationCode) { (fingerprint, error) in

    if error == nil {
        // No error occurred, proceed to credentials entry (PIN prompt, Enable Touch ID switch, ...) and commit
        // The 'fingerprint' value represents the device public key - it may be used as visual confirmation
    } else {
        // Error occurred, report it to the user
    }    

}
```

### Activation via Custom Credentials

You may also create an activation using any custom login data - it can be anything that server can use to obtain user ID to associate with a new activation. Since the credentials are custom, the endpoint that handles the custom activation must be set (standard RESTful API cannot be used).

Use following code to create an activation using custom credentials:

```swift
// Call reset to clear any pending activation data from previous attempts
PowerAuthSDK.sharedInstance().reset()

// Create a new activation with given device name and custom login credentials
let deviceName = "Petr's iPhone 7" // or UIDevice.current.name
let credentials = [
    "username": "john.doe@example.com",
    "password": "YBzBEM"
]
let url = URL(string: "https://localhost:8080/demo-server/session/login")

PowerAuthSDK.sharedInstance().createActivation(withName: deviceName, identityAttributes: credentials, url: url!) { (fingerprint, error) in
    if error == nil {
        // No error occurred, proceed to credentials entry (PIN prompt, Enable Touch ID switch, ...) and commit
        // The 'fingerprint' value represents the device public key - it may be used as visual confirmation
    } else {
        // Error occurred, report it to the user
    }
}
```

Note that by using weak identity attributes to create an activation, the resulting activation is confirming a "blurry identity". This may greately limit the legal weight and usability of a signature. We recommend using a strong identity verification before an activation can actually be created.

### Committing Activation Data

After you create an activation using one of the methods mentioned above, you need to commit the activation - to use provided user credentials to store the activation data on the device. Use following code to do this.

```swift
do {
    try PowerAuthSDK.sharedInstance().commitActivation(withPassword: "1234")
} catch _ {
    // happens only in case SDK was not configured or activation is not in state to be commited
}
```

This code has created activation with two factors: possession (key stored using a key derived from a device fingerprint) and knowledge (password, in our case a simple PIN code). If you would like to enable Touch or Face ID support at this moment, use following code instead of the one above:

```swift
do {
    let auth = PowerAuthAuthentication()
    auth.usePossession = true
    auth.usePassword   = "1234"
    auth.useBiometry   = true

    try PowerAuthSDK.sharedInstance().commitActivation(with: auth)
} catch _ {
    // happens only in case SDK was not configured or activation is not in state to be commited
}
```

## Requesting Activation Status

To obtain a detailed activation status information, use following code:

```swift
// Check if there is some activation on the device
if PowerAuthSDK.sharedInstance().hasValidActivation() {

    // If there is an activation on the device, check the status with server
    PowerAuthSDK.sharedInstance().fetchActivationStatus() { (status, customObject, error) in

        // If no error occurred, process the status
        if error == nil {

            // Activation state: .created, .otp_Used, .blocked, .removed
            let state: PA2ActivationState = status.state

            // Failed login attempts, remaining = max - current
            let currentFailCount = status.failCount
            let maxAllowedFailCount = status.maxFailCount
            let remainingFailCount = maxAllowedFailCount - currentFailCount

            // Custom object contains any proprietary server specific data


        } else {
            // Network error occurred, report it to the user
        }

    }

} else {
    // No activation present on device
}
```

## Data Signing

The main feature of PowerAuth 2.0 protocol is data signing. PowerAuth 2.0 has three types of signatures:

- **Symmetric Multi-Factor Signature**: Suitable for most operations, such as login, new payment or confirming changes in settings.
- **Asymmetric Private Key Signarture**: Suitable for documents, where strong one sided signature is desired.
- **Symmetric Offline Multi-Factor Signature**: Suitable for very secure operations, where the signature is validated over the out-of-band channel.
- **Verify server signed data**: Suitable for receiving arbitrary data from the server.

### Symmetric Multi-Factor Signature

To sign request data, you need to first obtain user credentials (password, PIN code, Touch ID scan) from the user. The task of obtaining the user credentials is used in more use-cases covered by the SDK. The core class is `PowerAuthAuthentication`, that holds information about used authentication factors:

```swift
// 2FA signature, uses device related key and user PIN code
let auth = PowerAuthAuthentication()
auth.usePossession = true
auth.usePassword   = "1234"
auth.useBiometry   = false
```

When signing `POST`, `PUT` or `DELETE` requests, use request body bytes (UTF-8) as request data and following code:

```swift
// 2FA signature, uses device related key and user PIN code
let auth = PowerAuthAuthentication()
auth.usePossession = true
auth.usePassword   = "1234"
auth.useBiometry   = false

// Sign POST call with provided data made to URI with custom identifier "/payment/create"
do {
    let signature = try PowerAuthSDK.sharedInstance().requestSignature(with: auth, method: "POST", uriId: "/payment/create", body: requestBodyData)
    let httpHeaderKey = signature.key
    let httpHeaderValue = signature.value
} catch _ {
    // In case of invalid configuration, invalid activation state or currupted state data
}
```

When signing `GET` requests, use the same code as above with normalized request data as described in specification, or (preferrably) use the following helper method:

```swift
// 2FA signature, uses device related key and user PIN code
let auth = PowerAuthAuthentication()
auth.usePossession = true
auth.usePassword   = "1234"
auth.useBiometry   = false

// Sign GET call with provided query parameters made to URI with custom identifier "/payment/create"
let params = [
    "param1": "value1",
    "param2": "value2"
]

do {
    let signature = try PowerAuthSDK.sharedInstance().requestGetSignature(with: auth, uriId: "/payment/create", params: params)
    let httpHeaderKey = signature.key
    let httpHeaderValue = signature.value
} catch _ {
    // In case of invalid configuration, invalid activation state or currupted state data
}
```

### Asymmetric Private Key Signature

Asymmetric Private Key Signature uses a private key stored in the PowerAuth 2.0 secure vault. In order to unlock the secure vault and retrieve the private key, user has to be first authenticated using a symmetric multi-factor signature with at least two factors. This mechanism protects the private key on the device - server plays a role of a "doorkeeper" and holds the vault unlock key.

This process is completely transparent on the SDK level. To compute an asymmetric private key signature, request user credentials (password, PIN, Touch ID scan) and use following code:

```swift
// 2FA signature, uses device related key and user PIN code
let auth = PowerAuthAuthentication()
auth.usePossession = true
auth.usePassword   = "1234"
auth.useBiometry   = false

// Unlock the secure vault, fetch the private key and perform data signing
PowerAuthSDK.sharedInstance().signData(withDevicePrivateKey: auth, data: data) { (signature, error) in
    if error == nil {
        // Send data and signature to the server
    } else {
        // Authentication or network error
    }
}
```

### Symmetric Offline Multi-Factor Signature

This type of signature is very similar to [Symmetric Multi-Factor Signature](#symmetric-multi-factor-signature) but the result is provided in form of simple, human readable string (unlike the online version, where the result is HTTP header). To calculate the signature you need a typical `PowerAuthAuthentication` object to define all required factors, nonce and data to sign. The `nonce` and `data` should be also transmitted to the application over the OOB channel (for example by scanning a QR code). Then the signature calculation is straightforward:

```swift
// 2FA signature, uses device related key and user PIN code
let auth = PowerAuthAuthentication()
auth.usePossession = true
auth.usePassword   = "1234"
auth.useBiometry   = false

do {
    let signature = try PowerAuthSDK.sharedInstance().offlineSignature(with: auth, uriId: "/confirm/offline/operation", body: data, nonce: nonce)
    print("Signature is " + signature)
} catch _ {
    // In case of invalid configuration, invalid activation state or other error
}
```

Now the application has to show that calculated signature to the user and user has to re-type that code into the web application for the verification.

### Verify server signed data

This task is useful when you need to receive an arbitrary data from the server and you need to be sure that data has has been issued by the server. The PowerAuthSDK is providing a high level method for validating data and associated signature:  

```swift
// Validate data signed with the master server key
if PowerAuthSDK.sharedInstance().verifyServerSignedData(data, signature: signature, masterKey: true) {
    // data is signed with server's private master key
}
// Validate data signed with the personalized server key
if PowerAuthSDK.sharedInstance().verifyServerSignedData(data, signature: signature, masterKey: false) {
    // data is signed with server's private key
}
```

## Password Change

Since the device does not know the password and is unable to verify the password without the help of the server side, you need to first call an endpoint that verifies a signature computed with the password. SDK offers two ways to do that.

The safe, but typically slower way is to use following code:

```swift
// Change password from "oldPassword" to "newPassword".
PowerAuthSDK.sharedInstance().changePassword(from: "oldPassword", to: "newPassword") { (error) in
    if error == nil {
        // Password was changed
    } else {
        // Error occurred
    }
}
```

This method calls `/pa/vault/unlock` under the hood with a 2FA signature with provided original password to verify the password correctness.

However, using this method does not usually fit to the typical UI workflow of a password change. The method may be used in cases where old password and new password are on a single screen, and therefore are both available at the same time. In most mobile apps, however, user first visits a screen to enter an old password and then (if the password is OK), the user proceeds to the two-screen flow of a new password setup (select password, confirm password). In other words, the workflow works like this:

1. Show a screen to enter old password.
2. Check old password on the server.
3. If the old password is OK, then let user chose and confirm a new one.
4. Change the password by "recrypting" the activation data.

For this purpose, you can use following code:

```swift
// Ask for old password
let oldPassword = "1234"

// Validate password on the server
PowerAuthSDK.sharedInstance().validatePasswordCorrect(oldPassword) { (error) in
    if error == nil {
        // Proceed to the new password setup
    } else {
        // Retry entering an old password
    }
}

// ...

// Ask for new password
let newPassword = "2468"

// Change the password locally
PowerAuthSDK.sharedInstance().unsafeChangePassword(from: oldPassword, to: newPassword)
```

**Now, beware!** Since the device does not know the actual old password, you need to make sure that the old password is validated before you use it in `unsafeChangePassword`. In case you provide a wrong old password, it will be used to decrypt the original data and these data will be encrypted using a new password. As a result, the activation data will be broken and irreversibly lost.

## Biometry Setup

PowerAuth SDK for iOS provides an abstraction on top of the base Touch and Face ID support. While the authentication / data signing itself is nicely and transparently embedded in `PowerAuthAuthentication` object used in [regular request signing](#data-signing), other biometry related processes require their own API.

### Check Biometry Status

You have to check for biometry on three levels:

- **System Availability**:
  - If Touch ID is present on the system and if iOS version is 9+
  - If Face ID is present on the system and if iOS version is 11+
- **Activation Availability**: If biometry factor data are available for given activation.
- **Application Availability**: If user decided to use Touch ID for given app. _(optional)_

PowerAuth SDK for iOS provides code for first two of these checks.

To check if you can use biometry on the system, use following code from `PA2Keychain` class:

```swift
// Is biometry available and is enrolled on the system?
let canUseBiometry = PA2Keychain.canUseBiometricAuthentication

// Or alternative, to get supported biometry type
let supportedBiometry = PA2Keychain.supportedBiometricAuthentication
switch supportedBiometry {
    case .touchID: print("You can use Touch ID")
    case .faceID: print("You can use Face ID")
    case .none: print("Biometry is not supported or not enrolled")
}

// Or more complex, with full information about type and current status
let biometryInfo = PA2Keychain.biometricAuthenticationInfo
switch biometryInfo.biometryType {
    case .touchID: print("Touch ID is available on device.")
    case .faceID: print("Face ID is available on device.")
    case .none: print("Biometry is not supported.")
}
switch biometryInfo.currentStatus {
    case .notSupported: print("Biometry is not supported.")
    case .notAvailable: print("Biometry is not available at this moment.")
    case .notEnrolled: print("Biometry is supported, but not enrolled.")
    case .lockout: print("Biometry is supported, but it has been locked out.")
    case .available: print("Biometry is available right now.")
}
```

To check if given activation has biometry factor related data available, use following code:

```swift
// Does activation have biometric factor related data in place?
let hasBiometryFactor = PowerAuthSDK.sharedInstance().hasBiometryFactor()
```

The last check is fully under your control. By keeping the biometry settings flag, for example a `BOOL` in `NSUserDefaults`, you are able to show expected user Touch or Face ID status (in disabled state, though) even in the case biometry is not enabled or when no finger or face is enrolled on the device.

### Enable Biometry

In case an activation does not yet have biometry related factor data and you would like to enable Touch or Face ID support, device must first retrieve the original private key from the secure vault for the purpose of key derivation. As a result, you have to use successful 2FA with password to enable biometry support.

Use following code to enable biometric authentication:

```swift
// Establish biometric data using provided password
PowerAuthSDK.sharedInstance().addBiometryFactor("1234") { (error) in
    if error == nil {
        // Everything went OK, Touch ID is ready to be used
    } else {
        // Error occurred, report it to user
    }
}
```

### Disable Biometry

You can remove biometry related factor data used by Touch or Face ID support by simply removing the related key locally, using this one-liner:

```swift
// Remove biometric data
PowerAuthSDK.sharedInstance().removeBiometryFactor()
```

## Activation Removal

You can remove activation using several ways - the choice depends on a desired behavior.

### Simple Device-Only Removal

You can clear activation data anytime from Keychain. The benefit of this method is that it does not require help from server and user does not have to be logged in. The issue with this removal method is simple: The activation still remains active on the server side. This, however, does not have to be an issue in your case.

To remove only data related to PowerAuth SDK for iOS, use `PA2Keychain` class:

```swift
PowerAuthSDK.sharedInstance().removeActivationLocal()
```

### Removal via Authenticated Session

In case your server uses an authenticated session for keeping user logged in, you can combine the previous method with calling your proprietary endpoint that removes activation for currently logged in user. The advantage of this method is that activation does not remain active on the server. The issue is that user has to be logged in (the session must be active and must have activation ID stored) and that you have to publish your own method for the purpose of this use case.

The code for this activation removal method is as follows:

```swift
// Use custom call to proprietary server endpoint to remove activation.
// User must be logged in at this moment, so that session can find
// associated activation ID
self.httpClient.post(null, "/custom/activation/remove") { (error) in
    if error == nil {
        PowerAuthSDK.sharedInstance().removeActivationLocal()
    } else {
        // Report error
    }
}

```

### Removal via Signed Request

PowerAuth 2.0 Standard RESTful API has a default endpoint `/pa/activation/remove` for an activation removal. This endpoint uses a signature verification for looking up the activation to be removed. The benefit of this method is that it is already present in both PowerAuth SDK for iOS and PowerAuth 2.0 Standard RESTful API - nothing has to be programmed. Also, user does not have to be logged in to use it. However, user has to authenticate using 2FA with either password or biometry.

Use following code for an activation removal using signed request:

```swift
// 2FA signature, uses device related key and user PIN code
let auth = PowerAuthAuthentication()
auth.usePossession = true
auth.usePassword   = "1234"
auth.useBiometry   = false

// Remove activation using provided authentication object
PowerAuthSDK.sharedInstance().removeActivation(with: auth) { (error) in
    if error == nil {
        // OK, activation was removed
    } else {
        // Report error to user
    }
}
```

## End-To-End Encryption

Currently, PowerAuth SDK for iOS has support for non-personalized (application key specific) encryption. You can use it to send encrypted data payload to server. Server has to be able to handle encrypted payload (decrypt request, encrypt response).

Encryption is technically carried out using an `PA2Encryptor` subclasses. Encryptors for given purpose are build using an `PA2EncryptorFactory` instance. You can easily obtain an encryptor factory right from the `PowerAuthSDK` shared instance, like so:

```swift
// Obtain the default encryptor factory
let encryptorFactory = PowerAuthSDK.sharedInstance().encryptorFactory
```

### Non-Personalized E2EE

To use non-personalized (application public key specific) encryption in your request / response cycle, build an appropriate encryptor and encrypt your data using following code:

```swift
do {
    // Obtain a correct encryptor
    let encryptor = encryptorFactory.buildRequestResponseNonPersonalizedEncryptor()

    // Prepare original request data
    let requestDictionary = ["requestKey": "requestVaue"]
    let requestData = try JSONSerialization.data(withJSONObject: requestDictionary)

    // Encrypt data using provided encryptor
    if let encryptedRequestData = try encryptor?.encryptRequest(requestData) {

        // Send encrypted request to your server endpoint
        self.httpClient.post(encryptedRequestData, "/custom/api/encrypted") { (httpResponse, error) in

            // Check if the communication with server succeed
            if error == nil {
                do {

                    // Decrypt response and obtain original response data
                    if let encryptedResponse = httpResponse as? PA2Response<PA2EncryptedObject> {
                        if let responseData = try encryptor?.decryptResponse(encryptedResponse) {

                            // Serialize response object
                            let responseDictionary = try JSONSerialization.jsonObject(with: responseData)

                            // DONE: Process the response dictionary
                            // ...

                        }
                    }
                } catch _ {
                    // in case response decryption (or JSON deserialization) fails
                }
            } else {
                // Report HTTP client error
            }
        }
    }
} catch {
    // in case request decryption (or JSON serialization) fails
}
```

Be careful here - you have to use the same instance of `PA2RequestResponseNonPersonalizedEncryptor` for both request and response. If you build one encryptor for request and another for response, encryption will not work - encryptor keeps an istance of ephemeral private key and this private key must be used for response decryption.

## Secure Vault

PowerAuth SDK for iOS has a basic support for an encrypted secure vault. At this moment, the only supported method allows application to establish an encryption / decryption key with given index. Index represents a "key number" - your identifier for given key. Different business logic purposes should have encryption keys with different index value.

On a server side, all secure vault related work is concentrated in a `/pa/vault/unlock` endpoint of PowerAuth 2.0 Standard RESTful API. In order to receive data from this response, call must be authenticated with at least 2FA (either password, or biometry).

### Obtaining Encryption Key

In order to obtain an encryption key with given index, use following code:

```swift
// 2FA signature, uses device related key and user PIN code
let auth = PowerAuthAuthentication()
auth.usePossession = true
auth.usePassword   = "1234"
auth.useBiometry   = false

// Select custom key index
let index = UInt64(1000)

// Fetch encryption key with given index
PowerAuthSDK.sharedInstance().fetchEncryptionKey(auth, index: index) { (encryptionKey, error) in
    if error == nil {
        // ... use encryption key to encrypt or decrypt data
    } else {
        // Report error
    }
}
```

## Token Based Authentication

WARNING: Before you start using access tokens, please visit our [wiki page for powerauth-crypto](https://github.com/wultra/powerauth-crypto/wiki/MAC-Token-Based-Authentication) for more information about this feature.

The tokens are simple, locally cached objects, producing timestamp-based authorization headers. Be aware that tokens are NOT a replacement for general PowerAuth signatures, but are helpful in situations, when the signatures are too heavy or too complicated for implementation. Each token has following properties:

- It needs PowerAuth signature for its creation (e.g. you need to provide `PowerAuthAuthentication` object)
- It has unique identifier on the server. This identifier is not exposed to the public API, but DEBUG version of SDK can reveal that identifier in the debugger (e.g. you can use `po tokenObject` to print object's description)
- It has symbolic name (e.g. "MyToken") defined by the application programmer to identify already created tokens.
- It can generate timestamp based authorization HTTP headers.
- Can be used concurrently. Token's private data doesn't change in time.
- The token is associated with the `PowerAuthSDK` instance. So, you can use the same symbolic name in multiple SDK instances and each created token will be unique.
- Tokens are persisted in the keychain and cached in the memory.
- Once the parent `PowerAuthSDK` instance loose its activation, then all its tokens are removed from the local database.

### Getting token

To get an access token, you can use following code:

```swift
// 1FA signature, uses device related key
let auth = PowerAuthAuthentication()
auth.usePossession = true

let tokenStore = PowerAuthSDK.sharedInstance().tokenStore

let task = tokenStore.requestAccessToken(withName: "MyToken", authentication: auth) { (token, error) in
    if let token = token {
        // now you can generate header
    } else {
        // handle error
    }
}
```

The request is performed synchronously or asynchronously depending on whether the token is locally cached on the device. You can test this situation by calling `tokenStore.hasLocalToken(withName: "MyToken")`. If operation is asynchronous, then `requestAccessToken()` returns cancellable task. Be aware that you should not issue multiple asynchronous operations for the same token name. Here's a more complex example:

```swift
private var tokenAcquireTask: Any?
private var tokenAcquireRequests: [(PowerAuthToken?, Error?)->Void] = []

func acquireToken(_ completion: @escaping (PowerAuthToken?, Error?)->Void) {
    let tokenStore = PowerAuthSDK.sharedInstance().tokenStore
    if let token = tokenStore.localToken(withName: "MyToken") {
        // token is available in local db
        completion(token, nil)
        return
    }
    // token is not locally available, remember that completion block
    tokenAcquireRequests.append(completion)
    if tokenAcquireTask == nil {
        // there's no pending request, create a new one
        let auth = PowerAuthAuthentication()
        auth.usePossession = true
        // now try to request for token
        tokenAcquireTask = tokenStore.requestAccessToken(withName: "MyToken", authentication: auth) { (token, error) in
            // we have result, report to all blocks
            self.tokenAcquireTask = nil
            self.tokenAcquireRequests.forEach { (block) in
                block(token, error)
            }
            self.tokenAcquireRequests.removeAll()
        }
    }
}

```
The complex example above is trying to hide that problematic asynchronous requesting with remembering completion blocks when the underlying HTTP request is already on the fly. Be aware that the code is still very simple PoC and for example, doesn't solve cancelation and thread safety.

### Generating authorization header

Once you have a `PowerAuthToken` object, use following code to generate an authorization header:

```swift
if let header = token.generateHeader() {
    let httpHeader = [ header.key : header.value ]
    // now you can attach that httpHeader to your HTTP request
} else {
    // in case of nil, token is no longer valid
}
```

### Removing token from server

To remove token from the server, you can use following code:

```swift
let tokenStore = PowerAuthSDK.sharedInstance().tokenStore
tokenStore.removeAccessToken(withName: "MyToken") { (removed, error) in
    if removed {
        // token has been removed
    } else {
        // handle error
    }
}
```

### Removing token locally

To remove token locally, you can simply use following code:

```swift
let tokenStore = PowerAuthSDK.sharedInstance().tokenStore
// Remove just one token
tokenStore.removeLocalToken(withName: "MyToken")
// Remove all local tokens
tokenStore.removeAllLocalTokens()
```

Note that removing tokens locally you'll loose control about tokens stored on the server.


## Apple Watch Support

This part of the documentation describes how to add support for Apple Watch into your PowerAuth powered IOS application.

### Prepare Watch Connectivity

The PowerAuth SDK for iOS is using [WatchConnectivity framework](https://developer.apple.com/documentation/watchconnectivity) to achieve data synchronization between iPhone and Apple Watch devices. If you're not familiar with this framework, then please take a look at least at [WCSession](https://developer.apple.com/documentation/watchconnectivity/wcsession) and [WCSessionDelegate](https://developer.apple.com/documentation/watchconnectivity/wcsessiondelegate) interfaces, before you start.

The PowerAuth SDK doesn't manage state of `WCSession` and doesn't set delegate to the session's singleton instance. It's up to you to properly configure and activate default session, but the application has to cooperate with PowerAuth SDK to process the messages received from the counterpart device. To do this, PowerAuth SDKs on both sides are providing `PA2WCSessionManager` class which can help you process all incoming messages. Here's an example, how you can implement simple `SessionManager` for IOS:

```swift
import Foundation
import WatchConnectivity
import PowerAuth2

class SessionManager: NSObject, WCSessionDelegate {

    static let shared = SessionManager()

    private let session: WCSession? = WCSession.isSupported() ? WCSession.default : nil

    // Returns false, when session is not available on the device.
    func activateSession() -> Bool {
        session?.delegate = self
        session?.activate()
        return session != nil
    }

    // MARK: - WCSessionDelegate

    func session(_ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: Error?) {
        if activationState == .activated {
            // now you can use WCSession for communication, send status of session to watch, etc...
        }
    }

    func sessionDidBecomeInactive(_ session: WCSession) {
        // session is now inactive
    }

    func sessionDidDeactivate(_ session: WCSession) {
        // session is now deactivated
    }

    func session(_ session: WCSession, didReceiveMessageData messageData: Data) {
        // Try to process PowerAuth messages...
        if PA2WCSessionManager.sharedInstance.processReceivedMessageData(messageData, replyHandler: nil) {
            return // processed...
        }
        // Other SDKs, or your own messages can be handler here...
        print("SessionManager.didReceiveMessageData did not process message.")
    }

    func session(_ session: WCSession, didReceiveMessageData messageData: Data, replyHandler: @escaping (Data) -> Void) {
        // Try to process PowerAuth messages...
        if PA2WCSessionManager.sharedInstance.processReceivedMessageData(messageData, replyHandler: replyHandler) {
            return // processed...
        }
        // Other SDKs, or your own messages can be handler here...
        print("SessionManager.didReceiveMessageData did not process message. Responding with empty data")
        replyHandler(Data())
    }

    func session(_ session: WCSession, didReceiveUserInfo userInfo: [String : Any] = [:]) {
        // Try to process PowerAuth messages...
        if PA2WCSessionManager.sharedInstance.processReceivedUserInfo(userInfo) {
            return // processed...
        }
        // Other SDKs, or your own messages can be handler here...
        print("SessionManager.didReceiveUserInfo did not process message.")
    }
}
```

*Note that the code above is very similar to its [watchOS counterpart](PowerAuth-SDK-for-watchOS.html#prepare-watch-connectivity)*

The example is implementing only a minimum set of methods from `WCSessionDelegate` protocol to make message passing work. The important is, that at some point, your both (iOS & watchOS) applications has to call `SessionManager.shared.activateSession()` to make transfers possible. Once you activate your session on the device, then you can use all APIs related to the communication.


### WCSession activation sequence

In this chapter we will discuss right initialization sequence for various interoperating objects during your application's startup. It's recommended to follow those rules to make communication between iOS & watchOS reliable.

#### tl;dr

On the application's startup:

1. Instantiate and configure all `PowerAuthSDK` instances and especially ones to be synchronized with Apple Watch.
2. Activate `WCSession`, so get the default instance, assign your delegate and call `activate()`
3. Wait for session's activation in your delegate
4. Now you can use watch related methods from PowerAuth SDK for iOS. For example, you can use lazy method to send status of activation to the watch device.

#### Implementation details

Due to our internal implementation details, each `PowerAuthSDK` instance is registered to `PA2WCSessionManager` for incoming message processing. The registration is done in object's designated init method and the de-registration is automatic, after the SDK object is destroyed. This technique works great, but depends on existence of right object at the right time.

So, once you activate `WCSession`, your `WCSessionDelegate` is going to get messages (on the background thread), received from the counterpart watch device. The reason why we're highlighting importance of right activation sequence is fact, that your watchOS application can wake up its iOS counterpart, so it's highly possible, that some messages will be available right at the application's startup. If you don't follow our rules and you'll not prepare your `PowerAuthSDK` instances before the `WCSession` is activated, then a couple of messages may be lost.

Fortunately, the situation on watchOS side is much easier, because all incoming messages are processed in one special service class, which is always available.



### Sending Activation Status to Watch

Before you start using PowerAuth on watchOS, it's recommended to send information about PowerAuth activation from iPhone to Apple Watch. The information transmitted to the watch is very limited. In fact, on watchOS side, you can check only whether the activation on iPhone is locally present or not. It is recommended to keep this status up to date as much as possible. That typically means that you may send status every time you complete or remove the activation.

To send current status of the activation, use following code:

```swift
if !PowerAuthSDK.sharedInstance().sendActivationStatusToWatch() {
    // send message has not been issued, WCSession is probably not available / active
} else {
    // message has been issued and it's guaranteed that it will be delivered to watch
}
```

There's also asynchronous version, but watch device has to be reachable at the time of the call:
```swift
PowerAuthSDK.sharedInstance().sendActivationStatusToWatch { (error) in
    if let error = error {
        // handle error, otherwise the transfer was OK
    }
}
```

*Note that sending status of `PowerAuthSDK` instance which is currently without activation also effectively remove all associated tokens from Apple Watch.*



### Sending Token to Watch

Once you have a `PowerAuthToken` object, use following code to send it to the Apple Watch:

```swift
if let token = tokenStore.localToken(withName: "MyToken") {
    if !token.sendToWatch() {
        // send message has not been issued, WCSession is probably not available / active
    } else {
        // message has been issued and it's guaranteed that it will be delivered to watch
    }
}
```

You can also use a different variant of the method with a completion block, but you have to be sure, that the Apple Watch is reachable at the time of call, otherwise the error is returned:

```swift
if let token = tokenStore.localToken(withName: "MyToken") {
    token.sendToWatch { (error) in
        if let error = error {
            // handle error, otherwise the transfer was OK
        }
    }
}
```

### Removing Token from Watch

You can remotely remove token from paired Apple Watch:

```swift
if let token = tokenStore.localToken(withName: "MyToken") {
    if !token.removeFromWatch() {
        // send message has not been issued, WCSession is probably not available / active
    } else {
        // message has been issued and it's guaranteed that it will be delivered to watch
    }
}
```

There's also asynchronous version, but paired watch has to be reachable at the time of the call:

```swift
if let token = tokenStore.localToken(withName: "MyToken") {
    token.removeFromWatch { (error) in
        if let error = error {
            // handle error, otherwise the transfer was OK
        }
    }
}
```


## Common SDK Tasks

### Error Handling

Most of the SDK methods return error object of an `NSError` class in case something goes wrong. Of course, it is your responsibility to handle errors these objects represent. There are two ways how you can obtain an error object from PowerAuth SDK for iOS.

In most cases, you receive an error object via a callback, like in this example:

```swift
PowerAuthSDK.sharedInstance().fetchActivationStatus { (status, customObject, error) in
    // Handle 'error' here
}
```

In other cases, you receive error via an exception, like in this example:

```swift
do {
    try PowerAuthSDK.sharedInstance().commitActivation(withPassword: "1234")
} catch let error as NSError {
    // Handle 'error' here
}
```

_Note: The original Objective-C code uses method with `BOOL` return type that passes `NSError**` (pointer to error object) as a method parameter. This syntax is automatically converted to exceptions when using code in Swift._

Errors that are caused by PowerAuth SDK for iOS use `PA2ErrorDomain` and one of the codes listed in `PA2ErrorConstants.h` file. Use these values to determine the type of an error. In principle, all errors should be in principle handled in a very similar manner. Use this code snippet for an inspiration:

```swift
if error == nil {
    // No error happened
} else {
    // Handle the error
    if let error = error as? NSError {

        // Is this a PowerAuth SDK for iOS error?
        if error.domain == PA2ErrorDomain {

            // If yes, handle the error based on the error code
            switch (error.code) {

            case PA2ErrorCodeNetworkError:
                print("Error code for error with network connectivity or download")

            case PA2ErrorCodeSignatureError:
                print("Error code for error in signature calculation")

            case PA2ErrorCodeInvalidActivationState:
                print("Error code for error that occurs when activation state is ivalid")

            case PA2ErrorCodeInvalidActivationData:
                print("Error code for error that occurs when activation data is ivalid")

            case PA2ErrorCodeMissingActivation:
                print("Error code for error that occurs when activation is required but missing")

            case PA2ErrorCodeAuthenticationFailed:
                print("Error code for error that occurs when authentication using PowerAuth signature fails")

            case PA2ErrorCodeActivationPending:
                print("Error code for error that occurs when pending activation is present and work with completed activation is required")

            case PA2ErrorCodeKeychain:
                print("Error code for keychanin related errors")

            case PA2ErrorCodeBiometryNotAvailable:
                print("Error code for TouchID/FaceID not available error")

            case PA2ErrorCodeBiometryCancel:
                print("Error code for TouchID/FaceID action cancel error")

            case PA2ErrorCodeOperationCancelled:
                print("Error code for cancelled operations")

            case PA2ErrorCodeEncryption:
                print("Error code for errors related to end-to-end encryption")

            case PA2ErrorCodeInvalidToken:
                print("Error code for errors related to token based auth.")

            case PA2ErrorCodeWatchConnectivity:
                print("Error code for errors related to synchronization between ios and watchos.")

            default:
                print("Unknown error")
            }
        }
    }
}
```

### Working with Invalid SSL Certificates

Sometimes, you may need to develop or test you application against a service that runs over HTTPS protocol with invalid (self-signed) SSL certificate. By default, HTTP client used in PowerAuth SDK communication validates certificate. To disable the certificate validation, add following code just before your `PowerAuthSDK` instance configuration:

```swift
// Set `PA2ClientSslNoValidationStrategy as the defauld client SSL certificate validation strategy`
PA2ClientConfiguration.sharedInstance().sslValidationStrategy = PA2ClientSslNoValidationStrategy()
```

*Note that since SDK version `0.18.0`, changing `PA2ClientConfiguration` no longer affects networking for previously instantiated `PowerAuthSDK` objects.*

## Additional Features

PowerAuth SDK for iOS contains multiple additional security features that are useful for mobile apps.

### Root Detection

You can easily detect if the device is jailbroken using following code:

```swift
// Check if the device is jailbroken using best effort attempt
let isJailbroken = PA2System.isJailbroken()
```

In case you would like to rely on a slightly more secure inline C code, use this way to perform the check:

```swift
// Check if the device is jailbroken using best effort attempt
let isJailbroken = pa_isJailbroken()
```

### Password Strength Indicator

Whenever user selects a password, you may estimate the password strength using following code:

```swift
// Determine the password strength: INVALID, WEAK, NORMAL, STRONG
let strength: PasswordStrength = PA2PasswordUtil.evaluateStrength("1234", passwordType: .PIN)
```

Passwords that are `INVALID` should block the progress. You should translate `WEAK` passwords to UI warnings (not blocking progress), `NORMAL` passwords to OK state, and `STRONG` passwords to rewarding UI message (so that we appreciate user selected strong password, without pushing the user to selecting strong password too hard).

Of course, you may apply any additional measures for the password validity and strength on top of the logics we provide.

### Debug build detection

It is sometimes useful to switch PowerAuth SDK to a DEBUG build configuration, to get more logs from the library:

- **CocoaPods:** a majority of the SDK is distributed as source codes, so it will match your application's build configuration. Only a low level C++ codes and several wrapper classes on top of those are precompiled into static library.
- **Manual installation:** Xcode is matching build configuration across all nested projects, so you usually don't need to care about the configuration switching.

The DEBUG build is usually helpful during the application development, but on other side, it's highly unwanted in production applications. For this purpose, the `PA2System.isInDebug()` method provides an information, whether the PowerAuth library was compiled in DEBUG configuration. It is a good practice to check this flag and crash the process when the production application is linked against the DEBUG PowerAuth:

```swift
#if YOUR_APPSTORE_BUILD_FLAG
    // Final vs Debug library trap
    if PA2System.isInDebug() {
        while true {
            print("CRITICAL ERROR: You're using Debug PowerAuth library in production build.")
            Thread.sleep(forTimeInterval: 1)
        }
    }
#endif
```
