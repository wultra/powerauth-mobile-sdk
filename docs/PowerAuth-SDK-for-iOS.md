# PowerAuth Mobile SDK for iOS and tvOS Apps

<!-- begin remove -->
## Table of Contents

- [Installation](#installation)
  - [Supported Platforms](#supported-platforms)
  - [CocoaPods Installation](#cocoapods)
  - [Manual Installation](#manual)
  - [Carthage Installation](#carthage)
- [Post-Installation Steps](#post-installation-steps)
  - [Include PowerAuth SDK in Your Sources](#include-powerauth-sdk-in-your-sources)
- [SDK Configuration](#configuration)
- [Device Activation](#activation)
  - [Activation via Activation Code](#activation-via-activation-code)
  - [Activation via OpenID Connect](#activation-via-openid-connect)
  - [Activation via Custom Credentials](#activation-via-custom-credentials)
  - [Activation via Recovery Code](#activation-via-recovery-code)
  - [Customize Activation](#customize-activation)
  - [Persisting Activation Data](#persisting-activation-data)
  - [Validating User Inputs](#validating-user-inputs)
- [Requesting Device Activation Status](#requesting-activation-status)
- [Data Signing](#data-signing)
  - [Symmetric Multi-Factor Signature](#symmetric-multi-factor-signature)
  - [Asymmetric Private Key Signature](#asymmetric-private-key-signature)
  - [Producing Signed JWT with Provided Claims](#producing-signed-jwt-with-provided-claims)
  - [Symmetric Offline Multi-Factor Signature](#symmetric-offline-multi-factor-signature)
  - [Verify Server-Signed Data](#verify-server-signed-data)
- [Password Change](#password-change)
- [Working with passwords securely](#working-with-passwords-securely)
- [Biometry Setup](#biometry-setup)
- [Biometry Troubleshooting](#biometry-troubleshooting)
- [Device Activation Removal](#activation-removal)
- [End-To-End Encryption](#end-to-end-encryption)
- [Secure Vault](#secure-vault)
- [Recovery Codes](#recovery-codes)
  - [Getting Recovery Data](#getting-recovery-data)
  - [Confirm Recovery Postcard](#confirm-recovery-postcard)
- [Token-Based Authentication](#token-based-authentication)
- [Apple Watch Support](#apple-watch-support)
  - [Prepare Watch Connectivity](#prepare-watch-connectivity)
  - [WCSession Activation Sequence](#wcsession-activation-sequence)
  - [Sending Activation Status to Watch](#sending-activation-status-to-watch)
  - [Sending Token to Watch](#sending-token-to-watch)
  - [Removing Token from Watch](#removing-token-from-watch)
- [External Encryption Key](#external-encryption-key)
- [Share Activation Data](#share-activation-data)
- [Synchronized Time](#synchronized-time)
- [Common SDK Tasks](#common-sdk-tasks)
- [Additional Features](#additional-features)
  - [Obtaining User's Claims](#obtaining-users-claims)
  - [Password Strength Indicator](#password-strength-indicator)
  - [Debug Build Detection](#debug-build-detection)
  - [Request Interceptors](#request-interceptors)  
- [Troubleshooting](#troubleshooting)

Related documents:

- [PowerAuth SDK for iOS App Extensions](./PowerAuth-SDK-for-iOS-Extensions.md)
- [PowerAuth SDK for watchOS](./PowerAuth-SDK-for-watchOS.md)
<!-- end -->

## Installation

This chapter describes how to get PowerAuth SDK for iOS and tvOS up and running in your app. In the current version, you can choose between CocoaPods and manual library integration.

### Supported Platforms

The library is available for the following Apple platforms:

- **iOS** 11.0+
- **mac Catalyst** 10.15+
- **tvOS** 11.0+

To simplify the documentation, we'll use **iOS** for the rest of the documentation and highlight the exceptions only. For example, **tvOS** doesn't support biometry and watch connectivity.

### CocoaPods

[CocoaPods](http://cocoapods.org) is a dependency manager for Cocoa projects. You can install it with the following command:
```bash
$ gem install cocoapods
```

To integrate the PowerAuth library into your Xcode project using CocoaPods, specify it in your `Podfile`:

```ruby
platform :ios, '11.0'
target '<Your Target App>' do
  pod 'PowerAuth2'
end
```

Then, run the following command:

```bash
$ pod install
```

### Swift Package Manager

If you wish to integrate the PowerAuth SDK into your app via SPM, please visit the [PowerAuth mobile SDK for Swift PM
](https://github.com/wultra/powerauth-mobile-sdk-spm)

### Manual

If you prefer not to use CocoaPods as a dependency manager, you can integrate PowerAuth into your project manually as a git [submodule](http://git-scm.com/docs/git-submodule).

#### Git Submodules

1. Open up the Terminal app and go to your top-level project directory and add the library as a submodule:
    ```sh
    $ git submodule add https://github.com/wultra/powerauth-mobile-sdk.git PowerAuthLib
    $ git submodule update --init --recursive
    ```
    The first command will clone PowerAuth SDK into the `PowerAuthLib` folder, and the second will update all nested submodules.

2. Open the new `PowerAuthLib` folder, and go to the `proj-xcode` sub-folder
3. Drag the `PowerAuthLib.xcodeproj` project file into **Project Navigator** of your application's Xcode project. It should appear nested underneath your application's blue project icon.
4. Select your application project in the Project Navigator to navigate to the target configuration window and select the extension's target under the **TARGETS** heading in the sidebar.
5. Now select **Build Phases** tab and expand the **Target Dependencies** section. Click on the "Plus Sign" and choose the **"PowerAuth2"** framework from the **"PowerAuthLib"** project.
6. Next, in the same **Build Phases** tab, expand **Link With Libraries** section. Click on the "Plus Sign" and choose the **"PowerAuth2.framework"** from the **"PowerAuthLib"** project.

### Carthage

We provide limited and experimental support for the [Carthage dependency manager](https://github.com/Carthage/Carthage). The current problem with Carthage is that we cannot specify which Xcode project and which scheme has to be used for a particular library build. It kind of works automatically, but the build process is extremely slow. So, if you still want to try to integrate our library with Carthage, try the following tips:

- Add `github "wultra/powerauth-mobile-sdk" "develop"` into your `Cartfile`. You can alternatively use any `release/X.Y.x` branch, greater or equal to `release/1.6.x`.
- It's recommended to force Carthage to use submodules for the library code checkouts.
- It's recommended to force Carthage to use XCFrameworks.
- It's recommended to update only the iOS platform (if possible). So try to run something like this: `carthage update --use-xcframeworks --use-submodules --platform ios`
- If the build fails on broken project `PowerAuthLib.xcodeproj` then go to `{your_project}/Carthage/Checkouts/powerauth-mobile-sdk/proj-xcode` and delete the `PowerAuthLib.xcodeproj` folder. This is because git doesn't delete empty folders by default and we have removed that XCode project from the source control. 
- Drop `PowerAuth2.xcframework` and `PowerAuthCore.xcframework` into your project.

## Configuration

To use PowerAuth SDK, simply add the following imports into your code:

```swift
// swift
import PowerAuth2
```

```objc
// Objective-C
@import PowerAuth2;
```

From now on, you can use `PowerAuthSDK` and other classes in your project. To configure your `PowerAuthSDK` instance, you need the following values from the PowerAuth Server:

- `MOBILE_SDK_CONFIG` - String that contains cryptographic configuration.

You also need to specify your instance ID (by default, this can be an app bundle ID). This is because one application may use more than one custom instance of `PowerAuthSDK`, and the identifier is the way to distinguish these instances while working with Keychain data.

Finally, you need to know the location of your [PowerAuth Standard RESTful API](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Standard-RESTful-API.md) endpoints. That path should contain everything that goes before the `/pa/**` prefix of the API endpoints.

To sum it up, in order to configure the `PowerAuthSDK` default instance, add the following code to your application delegate:

```swift
func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplicationLaunchOptionsKey: Any]?) -> Bool {

    // Prepare the configuration
    let configuration = PowerAuthConfiguration(
        instanceId: Bundle.main.bundleIdentifier!,
        baseEndpointUrl: "https://localhost:8080/demo-server",
        configuration: "ARDDj6EB6iAUtNm...KKEcBxbnH9bMk8Ju3K1wmjbA==")

    // Create a PowerAuthSDK instance with the configuration
    guard let powerAuth = PowerAuthSDK(configuration) else {
        // invalid configuration
        return false
    }

    return true
}
```

### Additional configuration

The `PowerAuthConfiguration` has the following additional properties:

- `offlineSignatureComponentLength` - Alters the default component length for the [offline signature](#symmetric-offline-multi-factor-signature). The values between 4 and 8 are allowed. The default value is 8.
- `externalEncryptionKey` - See [External Encryption Key](#external-encryption-key) chapter for more details.
- `disableAutomaticProtocolUpgrade` - If set to `true`, then automatic protocol upgrade is disabled. This option should be used only for the debugging purposes.
- `keychainKey_Biometry` - Specifies the 'key' used to store the `PowerAuthSDK` instance’s biometry-related key in the biometry keychain. If not set, the `instanceId` is applied. Do not alter this configuration unless you have a valid reason to do so.

### HTTP client configuration

The `PowerAuthClientConfiguration` object contains configuration for a HTTP client used internally by `PowerAuthSDK` object. It has the following configuration properties:

- `defaultRequestTimeout` - Property that specifies the default HTTP client request timeout. The default value is 20.0 seconds.
- `sslValidationStrategy` - Property that specifies the SSL validation strategy applied by the client. The default value is the default `URLSession` behavior. See [Working with Invalid SSL Certificates](#working-with-invalid-ssl-certificates) chapter for more details.
- `requestInterceptors`- Property that specifies the list of [request interceptors](#request-interceptors) used by the client before the request is executed. The default value is `nil`.
- `userAgent` -  Property that specifies the content of User-Agent request header. The default is value calculated in `PowerAuthSystem.defaultUserAgent()` function. If you set `nil` to this property, then the default value provided by operating system is used.

### Keychain configuration

The `PowerAuthKeychainConfiguration` object contains configuration for a keychain-based storage used by `PowerAuthSDK` class internally. The configuration contains the following properties:

- `keychainAttribute_AccessGroup` - Property that specifies a keychain access group in case that keychain is shared between multiple applications or between application and its extensions.
- `keychainAttribute_UserDefaultsSuiteName` - Property that specifies the name of `UserDefaults` suite to store the flag indicating that application has been re-installed. If the value is not provided, then `UserDefaults.standardUserDefaults` suite is used.
- `linkBiometricItemsToCurrentSet` - If set, then the item protected with the biometry is invalidated if fingers are added or removed for Touch ID, or if the user re-enrolls for Face ID. The default value is `false` (e.g. changing biometry in the system doesn't invalidate the entry)
- `allowBiometricAuthenticationFallbackToDevicePasscode` - If set to `true`, then the item protected with the biometry can be accessed also with a device passcode. If set, then `linkBiometricItemsToCurrentSet` option has no effect. The default is `false`, so fallback to device's passcode is not enabled.
- `invalidateLocalAuthenticationContextAfterUse` - If set to `true`, then the `LAContext` object provided by application is invalidated after the use in SDK. The default value is `true`, so `LAContext` cannot be reused for getting keys protected with biometry.

The following properties are also available for configuration but are not recommended to be altered under typical circumstances, as changing them may impact the library’s stability or intended behavior:

- `keychainInstanceName_Status` - Property that specifies the name of the Keychain service used to store statuses for different PowerAuth instances. You should not change this property unless you have a valid reason to do so.
- `keychainInstanceName_Possession` - Property that specifies the name of the Keychain service used to store possession factor related key (one value for all `PowerAuthSDK` instances).
- `keychainInstanceName_Biometry` - Property that specifies the name of the Keychain service used to store biometry related keys for different `PowerAuthSDK` instances.
- `keychainInstanceName_TokenStore` - Property that specifies the name of the Keychain service used to store content of `PowerAuthToken` objects.
- `keychainKey_Possession` - Property that specifies a storage key used to store possession fator related key in an associated possession Keychain service.


## Activation

After you configure the SDK instance, you are ready to make your first activation.

### Activation via Activation Code

The original activation method uses a one-time activation code generated in PowerAuth Server. To create an activation using this method, some external application (Internet banking, ATM application, branch / kiosk application) must generate an activation code for you and display it (as a text or in a QR code).

Use the following code to create an activation once you have an activation code:

```swift
let deviceName = "Petr's iPhone 7" // or UIDevice.current.name (see warning below)
let activationCode = "VVVVV-VVVVV-VVVVV-VTFVA" // let user type or QR-scan this value

// Create an activation object with the given activation code.
guard let activation = try? PowerAuthActivation(activationCode: activationCode, name: deviceName) else {
    // Activation code is invalid
}

// Create a new activation with just created activation object
powerAuthSDK.createActivation(activation) { (result, error) in
    if error == nil {
        // No error occurred, proceed to credentials entry (PIN prompt, Enable Touch ID switch, ...) and persist
        // The 'result' contains the 'activationFingerprint' property, representing the device public key - it may be used as visual confirmation
        // If the server supports recovery codes for activations, then the `activationRecovery` property contains an object with information about activation recovery.
    } else {
        // Error occurred, report it to the user
    }
}
```

If the received activation result also contains recovery data, then you should display those values to the user. To do that, please read the [Getting Recovery Data](#getting-recovery-data) section of this document, which describes how to treat that sensitive information. This is relevant for all types of activation you use.

<!-- begin box warning -->
Note that if you use `UIDevice.current.name` for a device’s name, your application must include an [appropriate entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_developer_device-information_user-assigned-device-name); otherwise, the operating system will provide a generic `iPhone` string.
<!-- end -->

#### Additional Activation OTP

If an [additional activation OTP](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Additional-Activation-OTP.md) is required to complete the activation, then use the following code to configure the `PowerAuthActivation` object:

```swift
let deviceName = "Petr's iPhone 7" // or UIDevice.current.name (see warning below)
let activationCode = "VVVVV-VVVVV-VVVVV-VTFVA" // let user type or QR-scan this value
let activationOtp = "12345"

// Create an activation object with the given activation code.
guard let activation = try? PowerAuthActivation(activationCode: activationCode, name: deviceName)?
    .with(additionalActivationOtp: activationOtp) else {
        // Activation code is invalid
}
// The rest of the activation routine is the same.
```

<!-- begin box warning -->
Be aware that OTP can be used only if the activation is configured for ON_KEY_EXCHANGE validation on the PowerAuth server. See our [crypto documentation for details](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Additional-Activation-OTP.md#regular-activation-with-otp).
<!-- end -->

### Activation via OpenID Connect

You may also create an activation using OIDC protocol:

```swift
// Create a new activation with a given device name and custom login credentials
let deviceName = "Petr's iPhone 7"  // or UIDevice.current.name (see warning below)
// Get the following information from your OpenID provider
let providerId = "1234567890abcdef"
let code = "1234567890abcdef"
let nonce = "K1mP3rT9bQ8lV6zN7sW2xY4dJ5oU0fA1gH29o"
let codeVerifier = "G3hsI1KZX1o~K0p-5lT3F7yZ4...6yP8rE2wO9n" // code verifier is optional

// create an activation object with the given OIDC parameters
guard let activation = try? PowerAuthActivation(oidcProviderId: providerId, code: code, nonce: nonce, codeVerifier: codeVerifier)
    .with(activationName: deviceName) else {
    // Activation parameter contains empty string
}
```

<!-- begin box warning -->
Note that if you use `UIDevice.current.name` for a device’s name, your application must include an [appropriate entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_developer_device-information_user-assigned-device-name); otherwise, the operating system will provide a generic `iPhone` string.
<!-- end -->

### Activation via Custom Credentials

You may also create an activation using any custom login data - it can be anything that the server can use to obtain the user ID to associate with a new activation. Since the credentials are custom, the server's implementation must be able to process such a request. Unlike the previous versions of SDK, the custom activation no longer requires a custom activation endpoint.

Use the following code to create an activation using custom credentials:

```swift
// Create a new activation with a given device name and custom login credentials
let deviceName = "Petr's iPhone 7" // or UIDevice.current.name (see warning below)
let credentials = [
    "username": "john.doe@example.com",
    "password": "YBzBEM"
]

// Create an activation object with the given credentials.
guard let activation = try? PowerAuthActivation(identityAttributes: credentials, name: deviceName) else {
    // Activation credentials are empty
}

// Create a new activation with just created activation object
powerAuthSDK.createActivation(activation) { (result, error) in
    if error == nil {
        // No error occurred, proceed to credentials entry (PIN prompt, Enable Touch ID switch, ...) and persist
        // The 'result' contains 'activationFingerprint' property, representing the device public key - it may be used as visual confirmation
        // If the server supports recovery codes for activations, then the `activationRecovery` property contains an object with information about activation recovery.
    } else {
        // Error occurred, report it to the user
    }
}
```

<!-- begin box warning -->
Note that by using weak identity attributes to create an activation, the resulting activation confirms a "blurry identity". This may greatly limit the legal weight and usability of a signature. We recommend using a strong identity verification before activation can actually be created.
<!-- end -->

<!-- begin box warning -->
Note that if you use `UIDevice.current.name` for a device’s name, your application must include an [appropriate entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_developer_device-information_user-assigned-device-name); otherwise, the operating system will provide a generic `iPhone` string.
<!-- end -->

### Activation via Recovery Code

If the PowerAuth Server is configured to support [Recovery Codes](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Activation-Recovery.md), then also you can create an activation via the recovery code and PUK.

Use the following code to create an activation using the recovery code:

```swift
let deviceName = "John Tramonta" // or UIDevice.current.name (see warning below)
let recoveryCode = "55555-55555-55555-55YMA" // User's input
let puk = "0123456789" // User's input. You should validate RC & PUK with using PowerAuthActivationCodeUtil

// Create activation object with recovery code and PUK
guard let activation = try? PowerAuthActivation(recoveryCode: recoveryCode, recoveryPuk: puk, name: deviceName) else {
    // Recovery code or PUK is not valid.
}

// Create a new activation with just created activation object
powerAuthSDK.createActivation(activation) { (result, error) in
    if let error = error {
        // Error occurred, report it to the user
        // On top of regular error processing, you should handle a special situation, when the server gives an additional information
        // about which PUK must be used for the recovery. The information is valid only when a recovery code from a postcard is applied.
        if let responseError = (error.userInfo[PowerAuthErrorDomain] as? PowerAuthRestApiErrorResponse)?.responseObject {
            let currentRecoveryPukIndex = responseError.currentRecoveryPukIndex
            if currentRecoveryPukIndex > 0 {
                // The PUK index is known, you should inform the user that it has to rewrite PUK from a specific position.
            }
        }
    } else {
        // No error occurred, proceed to credentials entry (PIN prompt, Enable Touch ID switch, ...) and persist
        // The 'result' contains the 'activationFingerprint' property, representing the device public key - it may be used as visual confirmation
        // If the server supports recovery codes for activations, then the `activationRecovery` property contains an object with information about activation recovery.
    }
}
```

<!-- begin box warning -->
Note that if you use `UIDevice.current.name` for a device’s name, your application must include an [appropriate entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_developer_device-information_user-assigned-device-name); otherwise, the operating system will provide a generic `iPhone` string.
<!-- end -->

### Customize Activation

You can set additional properties to the `PowerAuthActivation` object before any type of activation is created. For example:

```swift
// Custom attributes that can be processed before the activation is created on the PowerAuth Server.
// The dictionary may contain only values that can be serialized to JSON.
let customAttributes: [String:Any] = [
    "isNowPrimaryActivation" : true,
    "otherActivationIds" : [
        "e43f5f99-e2e9-49f2-bcae-5e32a5e96d22",
        "41dd704c-65e6-4d4b-b28f-0bc0e4eb9715"
    ]
]

// Extra flags that will be associated with the activation record on the PowerAuth Server.
let extraFlags = "EXTRA_FLAGS"

// Now create the activation object with all that extra data
guard let activation = try? PowerAuthActivation(activationCode: "45AWJ-BVACS-SBWHS-ABANA", name: activationName)?
    .with(extras: extraFlags)
    .with(customAttributes: customAttributes) else {
        // Invalid activation code...
    }

// Create a new activation as usual
powerAuthSDK.createActivation(activation) { (result, error) in
    //
}
```  

### Persisting Activation Data

After you create an activation using one of the methods mentioned above, you need to persist the activation - to use the provided user credentials to store the activation data on the device. Use the following code to do this:

```swift
do {
    try powerAuthSDK.persistActivation(withPassword: "1234")
} catch _ {
    // happens only in case SDK was not configured or activation is not in a state to be persisted
}
```

This code has created activation with two factors: possession (key stored using a key derived from a device fingerprint) and knowledge (password, in our case, a simple PIN code). If you would like to enable Touch or Face ID support at this moment, use the following code instead of the one above:

```swift
do {
    let auth = PowerAuthAuthentication.persistWithPasswordAndBiometry(password: "1234")

    try powerAuthSDK.persistActivation(with: auth)
} catch _ {
    // happens only in case SDK was not configured or activation is not in a state to be persisted
}
```


### Validating User Inputs

The mobile SDK provides a couple of functions in the `PowerAuthActivationCodeUtil` interface, helping with user input validation. You can:

- Parse activation code when it's scanned from QR code
- Validate a whole code at once
- Validate recovery code or PUK
- Auto-correct characters typed on the fly

#### Validating Scanned QR Code

To validate an activation code scanned from the QR code, you can use the `PowerAuthActivationCodeUtil.parse(fromActivationCode:)` function. You have to provide the code with or without the signature part. For example:

```swift
let scannedCode = "VVVVV-VVVVV-VVVVV-VTFVA#aGVsbG8......gd29ybGQ="
guard let otp = PowerAuthActivationCodeUtil.parse(fromActivationCode: scannedCode) else {
    // Invalid code
    return
}
guard let signature = otp.activationSignature else {
    // QR code should contain a signature
    return
}
```

Note that the signature is only formally validated in the function above. The actual signature verification is performed in the activation process, or you can do it on your own:

```swift
let scannedCode = "VVVVV-VVVVV-VVVVV-VTFVA#aGVsbG8......gd29ybGQ="
guard let otp = PowerAuthActivationCodeUtil.parse(fromActivationCode: scannedCode) else { return }
guard let signature = otp.activationSignature else { return }
if !powerAuthSDK.verifyServerSignedData(otp.activationCode.data(using: .utf8)!, signature: signature, masterKey: true) {
    // Invalid signature
}
```

#### Validating Entered Activation Code

To validate an activation code at once, you can call the `PowerAuthActivationCodeUtil.validateActivationCode()` function. You have to provide the code without the signature part. For example:

```swift
let isValid   = PowerAuthActivationCodeUtil.validateActivationCode("VVVVV-VVVVV-VVVVV-VTFVA")
let isInvalid = PowerAuthActivationCodeUtil.validateActivationCode("VVVVV-VVVVV-VVVVV-VTFVA#aGVsbG8gd29ybGQ=")
```

If your application is using your own validation, then you should switch to functions provided by SDK. The reason for that is that since SDK `1.0.0`, all activation codes contain a checksum, so it's possible to detect mistyped characters before you start the activation. Check our [Activation Code](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Activation-Code.md) documentation for more details.

#### Validating Recovery Code and PUK

To validate a recovery code at once, you can call the `PowerAuthActivationCodeUtil.validateRecoveryCode()` function. You can provide the whole code, which may or may not contain `"R:"` prefix. So, you can validate manually entered codes, but also codes scanned from QR. For example:

```swift
let isValid1 = PowerAuthActivationCodeUtil.validateRecoveryCode("VVVVV-VVVVV-VVVVV-VTFVA")
let isValid2 = PowerAuthActivationCodeUtil.validateRecoveryCode("R:VVVVV-VVVVV-VVVVV-VTFVA")
```

To validate PUK at once, you can call the `PowerAuthActivationCodeUtil.validateRecoveryPuk()` function:

```swift
let isValid   = PowerAuthActivationCodeUtil.validateRecoveryPuk("0123456789")
```

#### Auto-Correcting Typed Characters

You can implement auto-correcting of typed characters by using the `PowerAuthActivationCodeUtil.validateAndCorrectTypedCharacter()` function on screens, where the user is supposed to enter an activation or recovery code. This technique is possible because Base32 is constructed so that it doesn't contain visually confusing characters. For example, `1` (number one) and `I` (capital I) are confusing, so only `I` is allowed. The benefit is that the provided function can correct typed `1` and translate it to `I`.

Here's an example of how to iterate over the string and validate it character by character:

```swift
/// Returns corrected character or nil in case of error.
func validateAndCorrectCharacters(_ string: String) -> String? {
    var result : String = ""
    for codepoint in string.unicodeScalars {
        let newCodepoint = PowerAuthActivationCodeUtil.validateAndCorrectTypedCharacter(codepoint.value)
        if newCodepoint != 0 {
            // Valid, or corrected character
            result.append(Character(UnicodeScalar(newCodepoint)!))
        } else {
            return nil
        }
    }
    return result
}
```

## Requesting Activation Status

To obtain detailed activation status information, use the following code:

```swift
// Check if there is some activation on the device
if powerAuthSDK.hasValidActivation() {

    // If there is an activation on the device, check the status with the server
    powerAuthSDK.fetchActivationStatus() { (status, error) in

        // If no error occurred, process the status
        if let status = status {
            // Activation states are explained in detail in "Activation states" chapter below
            switch status.state {
            case .pendingCommit:
                print("Waiting for commit")
            case .active:
                print("Activation is active")
            case .blocked:
                print("Activation is blocked")
            case .removed:
                print("Activation is no longer valid")
                powerAuthSDK.removeActivationLocal()
            case .deadlock:
                print("Activation is technically blocked")
                powerAuthSDK.removeActivationLocal()
            case .created:
                // Activation is just created. This is the internal
                // state on the server and therefore can be ignored
                // on the mobile application.
                fallthrough
            default:
                print("Unknown state")
            }

            // Failed login attempts, remaining = max - current
            let currentFailCount = status.failCount
            let maxAllowedFailCount = status.maxFailCount
            let remainingFailCount = status.remainingAttempts

            if let customObject = status.customObject {
                // Custom object contains any proprietary server-specific data
            }

        } else {
            // Network error occurred, report it to the user
        }
    }

} else {
    // No activation present on the device
}
```

Note that the status fetch may fail at an unrecoverable error `PowerAuthErrorCode.protocolUpgrade`, meaning that it's not possible to upgrade the PowerAuth protocol to a newer version. In this case, it's recommended to [remove the activation locally](#activation-removal).

### Activation states

This chapter explains activation states in detail. To get more information about activation lifecycle, check the [Activation States](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Activation.md#activation-states) chapter available in our [powerauth-crypto](https://github.com/wultra/powerauth-crypto) repository.

#### `PowerAuthActivationState.created` 

The activation record is created using an external channel, such as the Internet banking, but the key exchange between the client and server did not happen yet. This state is never reported to the mobile client.

#### `PowerAuthActivationState.pendingCommig`

The activation record is created, and the key exchange between the client and server has already taken place, but the activation record on the server requires additional approval before it can be used. This approval is typically performed through an internet banking platform by the client or handled by an authorized representative in a back office system.

#### `PowerAuthActivationState.active`

The activation record is created and active. It is ready to be used for typical use-cases, such as generating signatures.

#### `PowerAuthActivationState.blocked` 

The activation record is blocked and cannot be used for most use-cases, such as generating signatures. While it can be unblocked and activated again, the unblock process cannot be performed locally on the mobile device and requires intervention through an external system, such as internet banking or a back office platform.

#### `PowerAuthActivationState.removed`

The activation record is removed and permanently blocked. It cannot be used for generating signatures or ever unblocked. You can inform user about this situation and remove the activation locally.

#### `PowerAuthActivationState.deadlock` 

The local activation is technically blocked and can no longer be used for signature calculations. You can inform the user about this situation and remove the activation locally.

The reason why the mobile client is no longer capable of calculating valid signatures is that the logical counter is out of sync between the client and the server. This may happen only if the mobile client calculates too many PowerAuth signatures without subsequent validation on the server. For example:

- If your application repeatedly constructs HTTP requests with a PowerAuth signature while the network is unreachable.
- If your application repeatedly creates authentication tokens while the network is unreachable. For example, when trying to register for push notifications in the background, without user interaction.
- If you calculate too many offline signatures without subsequent validation.

In rare situations, this may also happen in development or testing environments, where you’re able to restore the state of the activation on the server from a snapshot.

## Data Signing

The main feature of the PowerAuth protocol is data signing. PowerAuth has three types of signatures:

- **Symmetric Multi-Factor Signature**: Suitable for most operations, such as login, new payment, or confirming changes in settings.
- **Asymmetric Private Key Signature**: Suitable for documents where a strong one-sided signature is desired.
- **Symmetric Offline Multi-Factor Signature**: Suitable for very secure operations, where the signature is validated over the out-of-band channel.
- **Verify server signed data**: Suitable for receiving arbitrary data from the server.

### Symmetric Multi-Factor Signature

To sign request data, you need to first obtain user credentials (password, PIN code, Touch ID scan) from the user. The task of obtaining the user credentials is used in more use cases covered by the SDK. The core class is `PowerAuthAuthentication` that holds information about the used authentication factors:

```swift
// 1FA signature - uses device-related key only.
let oneFactor = PowerAuthAuthentication.possession()

// 2FA signature - uses device-related key and user PIN code.
let twoFactorPassword = PowerAuthAuthentication.possessionWithPassword(password: "1234")

// 2FA signature - uses biometry factor-related key as a 2nd. factor.
let twoFactorBiometry = PowerAuthAuthentication.possessionWithBiometry()

// Alternative biometry authentications with prompt
let twoFactorBiometryPrompt = PowerAuthAuthentication.possessionWithBiometry(prompt: "Please authenticate with biometry to log-in.")
```

When signing `POST`, `PUT`, or `DELETE` requests, use request body bytes (UTF-8) as request data and the following code:

```swift
// 2FA signature - uses device-related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

// Sign POST call with provided data made to URI with custom identifier "/payment/create"
do {
    let signature = try powerAuthSDK.requestSignature(with: auth, method: "POST", uriId: "/payment/create", body: requestBodyData)
    let httpHeaderKey = signature.key
    let httpHeaderValue = signature.value
} catch _ {
    // In case of invalid configuration, invalid activation state, or corrupted state data
}
```

When signing `GET` requests, use the same code as above with normalized request data as described in the specification, or (preferably) use the following helper method:

```swift
// 2FA signature - uses device-related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

// Sign GET call with provided query parameters made to URI with custom identifier "/payment/create"
let params = [
    "param1": "value1",
    "param2": "value2"
]

do {
    let signature = try powerAuthSDK.requestGetSignature(with: auth, uriId: "/payment/create", params: params)
    let httpHeaderKey = signature.key
    let httpHeaderValue = signature.value
} catch _ {
    // In case of invalid configuration, invalid activation state, or corrupted state data
}
```

#### Request Synchronization

It is recommended that your application executes only one signed request at a time. The reason for that is that our signature scheme uses a counter as a representation of logical time. In other words, the order of request validation on the server is very important. If you issue more than one signed request at the same time, then the order is not guaranteed, and therefore one of the requests may fail. On top of that, Mobile SDK itself is using this type of signature for its purposes. For example, if you ask for a token, then the SDK is using a signed request to obtain the token's data. To deal with this problem, Mobile SDK is providing a few methods that help with the signed requests synchronization.

If your networking is based on `OperationQueue`, then you can add your own `Operation` objects directly to the internal queue. Be aware that the PowerAuth signature must be calculated as a part of the operation's execution. For example:

```swift
let httpOperation: Operation = YourHttpOperation(...)
guard powerAuthSDK.executeOperation(onSerialQueue: httpOperation) else {
    fatalError("There's no activation")
}
```

In the case of custom networking, you can use the method to execute any block on the serial queue. In this case, the PowerAuth signature must be calculated as a part of the block's execution. For example:

```swift
powerAuthSDK.executeBlock(onSerialQueue: { internalTask in
    yourNetworking.post(yourRequest, completionHandler: { (data, response, error) in
        // Your response processing...
        // No matter what happens, you have to call the task.cancel() at the end
        internalTask.cancel()
    }, cancelationHandler: {
        // In case that your networking cancels the request, the given task
        // must be also canceled
        internalTask.cancel()
    })
})
```

### Asymmetric Private Key Signature

Asymmetric Private Key Signature uses a private key stored in the PowerAuth secure vault. To unlock the secure vault and retrieve the private key, the user has to first authenticate using the symmetric multi-factor signature with at least two factors. This mechanism protects the private key on the device - the server plays the role of a "doorkeeper" and holds the vault unlock key.

This process is completely transparent on the SDK level. To compute an asymmetric private key signature, request user credentials (password, PIN) and use the following code:

```swift
// 2FA signature - uses device-related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

// Unlock the secure vault, fetch the private key, and perform data signing
powerAuthSDK.signData(withDevicePrivateKey: auth, data: data) { (signature, error) in
    if error == nil {
        // Send data and signature to the server
    } else {
        // Authentication or network error
    }
}
```

### Producing Signed JWT with Provided Claims

The asymmetric private key signatures described above can be used to sign claims provided by the developer and construct a signed JWT (signed using the ES256 algorithm).

```swift
// Construct claims array
let claims = [
    "sub": "user-id",
    "first_name": "John",
    "last_name": "Appleseed"
]

// 2FA signature - uses device-related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

// Unlock the secure vault, fetch the private key, and perform data signing
powerAuthSDK.signJwt(withDevicePrivateKey: auth, claims: claims) { (jwt, error) in
    if let jwt {
        // Use JWT value
    } else {
        // Authentication or network error
    }
}
```

### Symmetric Offline Multi-Factor Signature

This type of signature is very similar to [Symmetric Multi-Factor Signature](#symmetric-multi-factor-signature), but the result is provided in the form of a simple, human-readable string (unlike the online version, where the result is an HTTP header). To calculate the signature, you need a typical `PowerAuthAuthentication` object to define all required factors, nonce, and data to sign. The `nonce` and `data` should also be transmitted to the application over the OOB channel (for example, by scanning a QR code). Then the signature calculation is straightforward:

```swift
// 2FA signature - uses device-related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

do {
    let signature = try powerAuthSDK.offlineSignature(with: auth, uriId: "/confirm/offline/operation", body: data, nonce: nonce)
    print("Signature is " + signature)
} catch _ {
    // In case of invalid configuration, invalid activation state, or other error
}
```

The application has to show that calculated signature to the user now, and the user has to re-type that code into the web application for verification. 

<!-- begin box info -->
You can alter the length of the signature components in the `offlineSignatureComponentLength` property of the `PowerAuthConfiguration` object.
<!-- end -->

### Verify Server-Signed Data

This task is useful whenever you need to receive arbitrary data from the server and you need to be able to verify that the server has issued the data. The PowerAuthSDK provides a high-level method for validating data and associated signatures:  

```swift
// Validate data signed with the master server key
if powerAuthSDK.verifyServerSignedData(data, signature: signature, masterKey: true) {
    // data is signed with the server's private master key
}
// Validate data signed with the personalized server key
if powerAuthSDK.verifyServerSignedData(data, signature: signature, masterKey: false) {
    // data is signed with the server's private key
}
```

## Password Change

Since the device does not know the password and is unable to verify the password without the help of the server side, you need to first call an endpoint that verifies a signature computed with the password. SDK offers two ways to do that.

The safe but typically slower way is to use the following code:

```swift
// Change password from "oldPassword" to "newPassword".
powerAuthSDK.changePassword(from: "oldPassword", to: "newPassword") { (error) in
    if error == nil {
        // Password was changed
    } else {
        // Error occurred
    }
}
```

This method calls `/pa/v3/signature/validate` under the hood with a 2FA signature with the provided original password to verify the password correctness.

However, using this method does not usually fit the typical UI workflow of a password change. The method may be used in cases where an old password and a new password are on a single screen, and therefore are both available at the same time. In most mobile apps, however, the user first visits a screen to enter an old password, and then (if the password is OK), the user proceeds to the two-screen flow of a new password setup (select password, confirm password). In other words, the workflow works like this:

1. Show a screen to enter an old password.
2. Check the old password on the server.
3. If the old password is OK, then let the user choose and confirm a new one.
4. Change the password by re-encrypting the activation data.

For this purpose, you can use the following code:

```swift
// Ask for an old password
let oldPassword = "1234"

// Validate password on the server
powerAuthSDK.validatePassword(password: oldPassword) { (error) in
    if error == nil {
        // Proceed to the new password setup
    } else {
        // Retry entering an old password
    }
}

// ...

// Ask for a new password
let newPassword = "2468"

// Change the password locally
powerAuthSDK.unsafeChangePassword(from: oldPassword, to: newPassword)
```

<!-- begin box warning -->
**Now, beware!** Since the device does not know the actual old password, you need to make sure that the old password is validated before you use it in `unsafeChangePassword`. In case you provide the wrong old password, it will be used to decrypt the original data, and these data will be encrypted using a new password. As a result, the activation data will be broken and irreversibly lost.
<!-- end -->


## Working with passwords securely

PowerAuth mobile SDK uses the `PowerAuthCorePassword` object behind the scene, to store the user's password or PIN securely. The object automatically wipes out the plaintext password on its destroy, so there are no traces of sensitive data left in the memory. You can easily enhance your application's runtime security by adopting this object in your code and this chapter explains in detail how to do it.

### Problem explanation

If you store the user's password in a simple string, there is a high probability that the content of the string will remain in the memory until the same region is reused by the underlying memory allocator. This is because the general memory allocator doesn't clean up the region of memory being freed. It just updates its linked list of free memory regions for future reuse, so the content of the allocated object typically remains intact. This has the following implications for your application:

- If your application is using a system keyboard to enter the password or PIN, then the sensitive data will remain in memory in multiple copies for a while. 

- If the device's memory is not stressed enough, then the application may remain in memory active for days.

The situation that the user's password stays in memory for days may be critical in situations when the attacker has the device in possession. For example, if the device is lost or is in a repair shop. To minimize the risks, the `PowerAuthCorePassword` object does the following things:

- Always keeps the user's password scrambled with random data, so it cannot be easily found by simple string search. The password in plaintext is revealed only for a short and well-defined time when it's needed for the cryptographic operation.

- Always clear the buffer with the sensitive data before the object's deinitialization.

- Doesn't provide a simple interface to reveal the password in plaintext<sup>1)</sup> and therefore it minimizes the risks of revealing the password by accident (like printing it to the log).

<!-- begin box info -->
**Note 1:** There's a `validatePasswordComplexity()` function that reveals the password in plaintext for a limited time for complexity validation purposes. The straightforward naming of the function allows you to find all its usages in your code and properly validate all code paths.
<!-- end -->

### Special password object usage

PowerAuth mobile SDK allows you to use both strings and special password objects at input, so it's up to you which way fits best for your purposes. For simplicity, this documentation uses strings for the passwords, but all code examples can be changed to utilize the `PowerAuthCorePassword` object as well. For example, this is the modified code for [Password Change](#password-change):

```swift
import PowerAuthCore

// Change password from "oldPassword" to "newPassword".
let oldPass = PowerAuthCorePassword(string: "oldPassword")
let newPass = PowerAuthCorePassword(string: "newPassword")
powerAuthSDK.changePassword(from: oldPass, to: newPass) { (error) in
    if error == nil {
        // Password was changed
    } else {
        // Error occurred
    }
}
```

### Entering PIN

If your application is using a system numeric keyboard to enter the user's PIN then you can migrate to the `PowerAuthCorePassword` object right now. We recommend you do the following things:

- Implement your own PIN keyboard UI

- Make sure that the password object is allocated and referenced only in the PIN keyboard controller and is deallocated when the user leaves the controller.

- Use `PowerAuthCoreMutablePassword` that allows you to manipulate the content of the PIN 

Here's the simple pseudo-controller example:

```swift
class EnterPinScene {
    let desiredPinLength = 4
    var pin: PowerAuthCoreMutablePassword!
    
    func onEnterScene() {
        // Allocate the pin when entering the scene
        pin = PowerAuthCoreMutablePassword()
    }
    
    func onLeaveScene() {
        // Dereference of the password object, when the user is leaving
        // the scene to safely wipe the content out of the memory
        pin = nil
    }
    
    func onDeleteButtonAction() {
        pin.removeLastCharacter()
    }

    func onPinButtonAction(pinCharacter: Character) {
        // Mutable password works with unicode scalars, this is the example
        // that works with an arbitrary character.
        pin.addCharacter(pinCharacter.unicodeScalars.first!.value)
        if pin.length() == desiredPinLength {
            onContinueAction(pin: pin)
        }
    }
    
    func onPinButtonActionSimplified(pinIndex: Int) {
        // This is a simplified version of onPinButtonAction() that use
        // simple PIN button index as input.
        guard pinIndex >= 0 && pinIndex <= 9 else { fatalError() }
        // You don't need to add 48 (code for character "0") to the index, 
        // unless your previous implementation was using number characters.
        pin.addCharacter(UInt32(pinIndex) + 48)
        if pin.length() == desiredPinLength {
            onContinueAction(pin: pin)
        }
    }
    
    func onContinueAction(pin: PowerAuthCorePassword) {
        // Do something with your pin...
    }
}
```

### Entering arbitrary password

Unfortunately, there's no simple solution for this scenario. It's quite difficult to re-implement the whole keyboard on your own, so we recommend you keep using the system keyboard. You can still create the `PowerAuthCorePassword` object from an already entered string:

```swift
let passwordString = "nbusr123"
let password = PowerAuthCorePassword(string: passwordString)
```

### Create a password from data

In case that passphrase is somehow created externally in the form of an array of bytes, then you can instantiate it from the `Data` object directly:

```swift
let passwordData = Data(base64Encoded: "bmJ1c3IxMjMK")!
let password = PowerAuthCorePassword(data: passwordData)
```

### Compare two passwords

To compare two passwords, use `isEqual(to:)` method:

```swift
let password1 = PowerAuthCorePassword(string: "1234")
let password2 = PowerAuthCorePassword(string: "Hello")
let password3 = PowerAuthCoreMutablePassword()
password3.addCharacter(0x31)
password3.addCharacter(0x32)
password3.addCharacter(0x33)
password3.addCharacter(0x34)
print("\(password1.isEqual(to: password2))")    // false
print("\(password1.isEqual(to: password3))")    // true
```

### Validate password complexity

The `PowerAuthCorePassword` object doesn't provide functions that validate password complexity, but allows you to implement such functionality on your own:

```swift
enum PasswordComplexity: Int {
    case weak = 0
    case good = 1
    case strong = 2
}

// This is an actual complexity validator that also accepts a pointer at its input. You should avoid
// converting provided memory into Data or String due to the fact, that it will lead to an uncontrolled
// passphrase copy to foundation objects' buffers.
func superPasswordValidator(passwordPtr: UnsafePointer<Int8>, size: Int) -> PasswordComplexity {
    // This is just an example, please do not use such trivial validation in your
    // production application :)
    if size < 4 {
        return .weak
    } else if size < 8 {
        return .good
    }
    return .strong
}

extension PowerAuthCorePassword {
    // Convenient wrapper to validateComplexity() method
    func validateComplexity() -> PasswordComplexity {
        let validationResult = self.validateComplexity { ptr, size in
            return superPasswordValidator(passwordPtr: ptr, size: size).rawValue
        }
        guard let complexity = PasswordComplexity(rawValue: validationResult) else { fatalError() }
        return complexity
    }
}
```

<!-- begin box info -->
You can use our [Passphrase meter](https://github.com/wultra/passphrase-meter) library as a proper password validation solution.
<!-- end -->

## Biometry Setup

PowerAuth SDK for iOS provides an abstraction on top of the base Touch and Face ID support. While the authentication / data signing itself is nicely and transparently embedded in the `PowerAuthAuthentication` object used in [regular request signing](#data-signing), other biometry-related processes require their own API. This part of the documentation is not relevant to the **tvOS** platform.

### Check Biometry Status

You have to check for biometry on three levels:

- **System Availability**:
  - If Touch ID is present on the system and if an iOS version is 9+
  - If Face ID is present on the system and if an iOS version is 11+
- **Activation Availability**: If biometry factor data are available for given activation.
- **Application Availability**: If the user decides to use Touch ID for a given app. _(optional)_

PowerAuth SDK for iOS provides code for the first two of these checks.

To check if you can use biometry on the system, use the following code from the `PowerAuthKeychain` class:

```swift
// Is biometry available and is enrolled in the system?
let canUseBiometry = PowerAuthKeychain.canUseBiometricAuthentication

// Or alternative, to get supported biometry type
let supportedBiometry = PowerAuthKeychain.supportedBiometricAuthentication
switch supportedBiometry {
    case .touchID: print("You can use Touch ID")
    case .faceID: print("You can use Face ID")
    case .none: print("Biometry is not supported or not enrolled")
}

// Or more complex, with full information about the type and current status
let biometryInfo = PowerAuthKeychain.biometricAuthenticationInfo
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

To check if a given activation has biometry factor-related data available, use the following code:

```swift
// Does activation have biometric factor-related data in place?
let hasBiometryFactor = powerAuthSDK.hasBiometryFactor()
```

The last check is fully under your control. By keeping the biometry settings flag, for example, a `BOOL` in `NSUserDefaults`, you are able to show expected user Touch or Face ID status (in a disabled state, though) even in the case biometry is not enabled or when no finger or face is enrolled on the device.

### Enable Biometry

In case an activation does not yet have biometry-related factor data, and you would like to enable Touch or Face ID support, the device must first retrieve the original private key from the secure vault for the purpose of key derivation. As a result, you have to use a successful 2FA with a password to enable biometry support.

Use the following code to enable biometric authentication:

```swift
// Establish biometric data using the provided password
powerAuthSDK.addBiometryFactor(password: "1234") { (error) in
    if error == nil {
        // Everything went OK, Touch ID is ready to be used
    } else {
        // Error occurred, report it to the user
    }
}
```

### Disable Biometry

You can remove biometry-related factor data used by Touch or Face ID support by simply removing the related key locally, using this one-liner:

```swift
// Remove biometric data
powerAuthSDK.removeBiometryFactor()
```

### Fetch Biometry Credentials In Advance

You can acquire biometry credentials in advance in case business processes require computing two or more different PowerAuth biometry signatures in one interaction with the user. To achieve this, the application must acquire the custom-created `PowerAuthAuthentication` object first and then use it for the required signature calculations. It's recommended to keep this instance referenced only for a limited time, required for all future signature calculations.

Be aware, that you must not execute the next HTTP request signed with the same credentials when the previous one fails with the 401 HTTP status code. If you do, then you risk blocking the user's activation on the server.

To obtain biometry credentials for the future signature calculation, call the following code:

```swift
// Authenticate user with biometry and obtain PowerAuthAuthentication credentials for future signature calculation.
powerAuthSDK.authenticateUsingBiometry(withPrompt: "Authenticate to sign in") { authentication, error in
    if let authentication = authentication {
        // Success, you can use the provided PowerAuthAuthentication object for the signature calculation.
        // The provided authentication object is preconfigured for possession+biometry factors
    }
    guard let error = error as NSError?, error.domain == PowerAuthErrorDomain else {
        return // should never happen
    }
    if error.powerAuthErrorCode == .biometryCancel {
        // User did cancel the operation
    } else {
        // Other error
    }
}
```

### Biometry Factor-Related Key Lifetime

By default, the biometry factor-related key is **NOT** invalidated after the biometry enrolled in the system is changed. For example, if the user adds or removes the finger or enrolls with a new face, then the biometry factor-related key is still available for the signing operation. To change this behavior, you have to provide the `PowerAuthKeychainConfiguration` object with the `linkBiometricItemsToCurrentSet` parameter set to `true` and use that configuration for the `PowerAuthSDK` instance construction:

```swift
// Prepare your PA config
let configuration = PowerAuthConfiguration()
// ...

// Prepare PowerAuthKeychainConfiguration
// Set true to the 'linkBiometricItemsToCurrentSet' property.
let keychainConfiguration = PowerAuthKeychainConfiguration()
keychainConfiguration.linkBiometricItemsToCurrentSet = true

// Init PowerAuthSDK instance
let powerAuthSDK = PowerAuthSDK(configuration: configuration, keychainConfiguration: keychainConfiguration, clientConfiguration: nil)
```

<!-- begin box warning -->
Be aware that the configuration above is effective only for the new keys. So, if your application is already using the biometry factor-related key with a different configuration, then the configuration change doesn't change the existing key. You have to [disable](#disable-biometry) and [enable](#enable-biometry) biometry to apply the change.
<!-- end -->

### Fallback biometry to device passcode

By default, the fallback from biometric authentication to authenticate with the device's passcode is not allowed. To change this behavior, you have to provide the `PowerAuthKeychainConfiguration` object with the `allowBiometricAuthenticationFallbackToDevicePasscode` parameter set to `true` and use that configuration for the `PowerAuthSDK` instance construction:

```swift
// Prepare your PA config
let configuration = PowerAuthConfiguration()
// ...

// Prepare PowerAuthKeychainConfiguration
// Set true to the 'allowBiometricAuthenticationFallbackToDevicePasscode' property.
let keychainConfiguration = PowerAuthKeychainConfiguration()
keychainConfiguration.allowBiometricAuthenticationFallbackToDevicePasscode = true

// Init PowerAuthSDK instance
let powerAuthSDK = PowerAuthSDK(configuration: configuration, keychainConfiguration: keychainConfiguration, clientConfiguration: nil)
``` 

Once the configuration above is used, then the `linkBiometricItemsToCurrentSet` option does not affect the biometry factor-related key lifetime. 

<!-- begin box warning -->
It's not recommended to allow fallback to device passcodes if your application falls under EU banking regulations or your application needs to distinguish between the biometric and the knowledge-factor-based signatures. This is because if the biometry factor-related key is unlocked with the device's passcode, then it's no longer a biometric signature.
<!-- end -->

### LAContext support

In case you require advanced customization to the system biometric dialog, then you can use your own `LAContext` instance set to `PowerAuthAuthentication` or in some functions. For example:

```swift
// Prepare LAContext
let laContext = LAContext()
laContext.localizedReason = "Authenticate to remove activation"

// Prepare PowerAuthAuthentication with context
let authentication = PowerAuthAuthentication.possessionWithBiometry(context: laContext)
// Now you can use authentication in some functions...
powerAuthSDK.removeActivation(with: authentication) { error in
    // ...
}

// Fetch the biometry key in advance using LAContext
powerAuthSDK.authenticateUsingBiometry(withContext: laContext) { authentication, error in
    if let authentication = authentication {
        // success
    }
}
```

The usage of `LAContext` has the following limitations:

- It's effective from iOS 11 because on the older operating systems, the context doesn't support essential properties, such as `localizedReason`.
- Don't alter the `interactionNotAllowed` property. If you do, then the internal SDK implementation rejects the context, and an error is reported.

Be aware that PowerAuth automatically invalidates the application provided `LAContext` after use. This is because once the context is successfully evaluated then it can be used for a quite long time to fetch the data protected with the biometry with no prompt displayed. The exact time of validity is undocumented, but our experiments show that iOS prompts for biometric authentication again after more than 5 minutes.

If you plan to pre-authorize `LAContext` and use it for multiple biometry signature calculations in a row, then please consider the following things first:

- Make sure that you make context invalid once it's no longer needed.
- Multiple signatures in a row could be problematic if your application falls under EU banking regulations.
- It would be difficult to prove that the user authorized the request if your application contains a bug and does the signature on the user's behalf or with the wrong context.

If you still insist to re-use `LAContext` then you have to alter `PowerAuthKeychainConfiguration` and set `invalidateLocalAuthenticationContextAfterUse` to `false`.


## Biometry troubleshooting

### Biometry lockout

<!-- begin box warning -->
Note that if the biometric authentication fails with too many attempts in a row (e.g. biometry is locked out), then PowerAuth SDK will generate an invalid biometry factor-related key, and the success is reported back to the application. This is an intended behavior and as a result, it typically leads to unsuccessful authentication on the server and an increased counter of failed attempts. The purpose of this is to limit the number of attempts for attackers to deceive the biometry sensor.
<!-- end -->

### Thread-blocking operation

Be aware that if you try to calculate PowerAuth Symmetric Signature with a biometric factor, then the call to the SDK function will block the calling thread while the biometric authentication dialog is displayed. So, it's not recommended to do such an operation on the main thread. For example:

```swift
let authentication = PowerAuthAuthentication.possessionWithBiometry()
let header = try? sdk.requestSignature(with: authentication, method: "POST", uriId: "/some/uri-id", body: "{}".data(using: .utf8))
// The thread is blocked while the biometric dialog is displayed.
```

### Parallel biometric authentications

It's not recommended to calculate more than one signature with the biometric factor at the same time, or in a row at a quick pace. Both scenarios are considered an issue in the application's logic.

To prevent the first case, PowerAuth mobile SDK is using a global mutex that guarantees that only one attempt to get the biometry-protected data at the time is performed. If your application issues another signing operation while the system dialog is displayed, then this attempt ends with `.biometryCancel` error.

There's another similar issue on devices supporting FaceID. The FaceID technology behaves slightly differently than TouchID and if you try to use biometry too soon after a previous successful authentication, then the 2nd attempt will fail with an authentication error. This is undocumented, but we believe it's related to the animation presented to the user after successful authentication. You simply cannot request another biometric authentication while the animation is still playing.
 

### Use pre-authorized LAContext

If you want more control over the biometric authentication UI flow, then you can prepare `LAContext` and evaluate it on your own. The pre-authorized context can be then used to construct `PowerAuthAuthentication`:

```swift
let context = LAContext()
context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Please authenticate with biometry") { success, error in
    guard success && error == nil else {
        // Biometric error handling
        return
    }
    let authentication = PowerAuthAuthentication.possessionWithBiometry(context: context)
    // Now you can use the authentication object in any SDK function that accepts authentication with a biometric factor.
}
```

Be aware that the example above doesn't handle all quirks related to the PowerAuth protocol, so you should prefer to use the `authenticateUsingBiometry()` function instead:

```swift
let context = LAContext()
context.localizedReason = "Please authenticate with biometry"
powerAuthSDK.authenticateUsingBiometry(withContext: context) { authentication, error in
    guard let authentication = authentication else {
        if let nsError = error as? NSError {
            if nsError.domain == PowerAuthErrorDomain {
                if nsError.powerAuthErrorCode == .biometryCancel {
                    // cancel, app cancel, system cancel...
                } else if nsError.powerAuthErrorCode == .biometryFallback {
                    // fallback button pressed
                }
                // If you're interested in the exact failure reason, then extract
                // the underlying LAError.
                if let laError = nsError.userInfo[NSUnderlyingErrorKey] as? LAError {
                    // Investigate error codes...
                }
            }   
        }
        return
    }
    // Now use authentication in other APIs
}
```

## Activation Removal

You can remove activation using several ways - the choice depends on the desired behavior.

### Simple Device-Only Removal

You can clear activation data anytime from the Keychain. The benefit of this method is that it does not require help from the server, and the user does not have to be logged in. The issue with this removal method is simple: The activation still remains active on the server side. This, however, does not have to be an issue in your case.

To remove only data related to PowerAuth SDK for iOS, use the `PowerAuthKeychain` class:

```swift
powerAuthSDK.removeActivationLocal()
```

### Removal via Authenticated Session

Suppose your server uses an authenticated session to keep the users logged in. In that case, you can combine the previous method with calling your proprietary endpoint to remove activation for the currently logged-in user. The advantage of this method is that activation does not remain active on the server. The issue is that the user has to be logged in (the session must be active and must have an activation ID stored) and that you have to publish your own method to handle this use case.

The code for this activation removal method is as follows:

```swift
// Use custom call to proprietary server endpoint to remove activation.
// The user must be logged in at this moment, so that the session can find
// associated activation ID
self.httpClient.post(null, "/custom/activation/remove") { (error) in
    if error == nil {
        powerAuthSDK.removeActivationLocal()
    } else {
        // Report error
    }
}

```

### Removal via Signed Request

PowerAuth Standard RESTful API has a default endpoint `/pa/v3/activation/remove` for an activation removal. This endpoint uses a signature verification for looking up the activation to be removed. The benefit of this method is that it is already present in both PowerAuth SDK for iOS and PowerAuth Standard RESTful API - nothing has to be programmed. Also, the user does not have to be logged in to use it. However, the user has to authenticate using 2FA with either a password or biometry.

Use the following code for an activation removal using a signed request:

```swift
// 2FA signature - uses device-related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

// Remove activation using the provided authentication object
powerAuthSDK.removeActivation(with: auth) { (error) in
    if error == nil {
        // OK, activation was removed
    } else {
        // Report error to user
    }
}
```

## End-To-End Encryption

Currently, PowerAuth SDK supports two basic modes of end-to-end encryption, based on the ECIES scheme:

- In an "application" scope, the encryptor can be acquired and used during the whole lifetime of the application.
- In an "activation" scope, the encryptor can be acquired only if `PowerAuthSDK` has a valid activation. The encryptor created for this mode is cryptographically bound to the parameters agreed during the activation process. You can combine this encryption with [PowerAuth Symmetric Multi-Factor Signature](#symmetric-multi-factor-signature) in "encrypt-then-sign" mode.

For both scenarios, you need to acquire the `PowerAuthCoreEciesEncryptor` object, which will then provide an interface for the request encryption and the response decryption. The object currently provides only low-level encryption and decryption methods, so you need to implement your own JSON (de)serialization and request and response processing.

The following steps are typically required for a full E2EE request and response processing:

1. Acquire the right encryptor from the `PowerAuthSDK` instance. For example:
   ```swift
   // Import PowerAuthCore to access ECIES implementation
   import PowerAuthCore
   
   // Encryptor for "application" scope.
   sdk.eciesEncryptorForApplicationScope { encryptor, error in
      if let encryptor {
        // success
      } else {
        // failure
      }
   }
   // ...or similar, for an "activation" scope.
   sdk.eciesEncryptorForActivationScope { encryptor, error in
      if let encryptor {
        // success
      } else {
        // failure
      }
   }
   ```

1. Serialize your request payload, if needed, into a sequence of bytes. This step typically means that you need to serialize your model object into a JSON-formatted sequence of bytes.

1. Encrypt your payload:
   ```swift
   guard let cryptogram = encryptor.encryptRequest(payloadData) else { ...failure... }
   ```

1. Construct a JSON from the provided cryptogram object:
   ```swift
   guard let requestBody = try? JSONSerialization.data(withJSONObject: cryptogram.requestPayload()) else { ...failure... }
   ```
   So, the final request JSON should look like this:
   ```json
   {
      "temporaryKeyId" : "UUID",
      "ephemeralPublicKey" : "BASE64-DATA-BLOB",
      "encryptedData" : "BASE64-DATA-BLOB",
      "mac" : "BASE64-DATA-BLOB",
      "nonce" : "BASE64-NONCE",
      "timestamp" : 1694172789256
   }
   ```

1. Add the following HTTP header (for signed requests, see note below):
   ```swift
   // Acquire a "metadata" object, which contains additional information for the request construction
   guard let metadata = encryptor.associatedMetaData else { ...should never happen... }
   let httpHeaderName = metadata.httpHeaderKey
   let httpHeaderValue = metadata.httpHeaderValue
   ```
   Note that if an "activation" scoped encryptor is combined with PowerAuth Symmetric Multi-Factor signature, then this step is not required. The signature's header already contains all the information required for proper request decryption on the server.

1. Fire your HTTP request and wait for a response
   - In case that non-200 HTTP status code is received, then the error processing is identical to a standard RESTful response defined in our protocol. So, you can expect a JSON object with `"error"` and `"message"` properties in the response.

1. Decrypt the response. The received JSON response typically looks like this:
   ```json
   {
      "encryptedData": "BASE64-DATA-BLOB",
      "mac": "BASE64-DATA-BLOB",
      "nonce": "BASE64-NONCE",
      "timestamp": 1694172789256
   }
   ```
   So, you need to create yet another "cryptogram" object:
   ```swift
   guard let response = try? JSONSerialization.jsonObject(with: responseBody) else { ...failure... }
   guard let responseCryptogram = PowerAuthCoreEciesCryptogram(responsePayload: response) else { ...not a dictionary... }
   guard let responseData = encryptor.decryptResponse(responseCryptogram) else { ... failed to decrypt data ... }
   ```

1. And finally, you can process your received response.

As you can see, the E2EE is quite a non-trivial task. We recommend contacting us before using an application-specific E2EE. We can provide you with more support on a per-scenario basis, especially if we first understand what you are trying to achieve with end-to-end encryption in your application.

## Secure Vault

PowerAuth SDK for iOS has basic support for an encrypted secure vault. At this moment, the only supported method allows your application to establish an encryption / decryption key with a given index. The index represents a "key number" - your identifier for a given key. Different business logic purposes should have encryption keys with different index values.

On the server side, all secure vault-related work is concentrated in a `/pa/v3/vault/unlock` endpoint of PowerAuth Standard RESTful API. In order to receive data from this response, the call must be authenticated with at least 2FA (using a password or PIN).

<!-- begin box warning -->
The secure vault mechanism does not support biometry by default. Use PIN code or password-based authentication for unlocking the secure vault, or ask your server developers to enable biometry for vault unlock calls by configuring the PowerAuth Server instance.
<!-- end -->

### Obtaining Encryption Key

To obtain an encryption key with a given index, use the following code:

```swift
// 2FA signature. It uses a device-related key and user PIN code.
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

// Select custom key index
let index = UInt64(1000)

// Fetch the encryption key with the given index
powerAuthSDK.fetchEncryptionKey(auth, index: index) { (encryptionKey, error) in
    if error == nil {
        // ... use the encryption key to encrypt or decrypt data
    } else {
        // Report error
    }
}
```

## Recovery Codes

The recovery codes allow your users to recover their activation in case their device is lost or stolen. Before you start, please read the [Activation Recovery](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Activation-Recovery.md) document, available in our [powerauth-crypto](https://github.com/wultra/powerauth-crypto) repository.

To recover an activation, the user has to re-type two separate values:

1. Recovery Code itself, which is very similar to an activation code. So you can detect typing errors before you submit such code to the server.
1. PUK, which is an additional numeric value and acts as a one-time password in the scheme.

PowerAuth currently supports two basic types of recovery codes:

1. Recovery Code bound to a previous PowerAuth activation.
   - This type of code can be obtained only in an already-activated application.
   - This type of code has only one PUK available, so only one recovery operation is possible.
   - The activation associated with the code is removed once the recovery operation succeeds.

2. Recovery Code delivered via OOB channel, typically in the form of a securely printed postcard, delivered by the post service.
   - This type of code has typically more than one PUK associated with the code, so it can be used multiple times.
   - The user has to keep that postcard in a safe and secure place, and mark already used PUKs.
   - The code delivery must be confirmed by the user before the code can be used for a recovery operation.

The feature is not automatically available. It must be enabled and configured on the PowerAuth Server. If it's so, then your mobile application can use several methods related to this feature.

### Getting Recovery Data

If the recovery data was received during the activation process, then you can later display that information to the user. To check the existence of recovery data and get that information, use the following code:

```swift
guard powerAuthSdk.hasActivationRecoveryData() else {
    // Recovery information is not available
    return
}

// 2FA signature - uses device-related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

powerAuthSdk.activationRecoveryData(auth) { recoveryData, error in
    if let recoveryData = recoveryData {
        let recoveryCode = recoveryData.recoveryCode
        let puk = recoveryData.puk
        // Show values on the screen
    } else {
        // Show an error
    }
}
```

The obtained information is very sensitive, so you should be very careful how your application manipulates the received values:

- You should never store `recoveryCode` or `puk` on the device.
- You should never print the values to the debug log.
- You should never send the values over the network.
- You should never copy the values to the clipboard.
- You should require a PIN code every time to display the values on the screen.
- You should warn the user that taking a screenshot of the values is not recommended.
- Do not cache the values in RAM.

You should inform the user that:

- Making a screenshot when values are displayed on the screen is dangerous.
- The user should write down those values on paper and keep it as safe as possible for future use.


### Confirm Recovery Postcard

The recovery postcard can contain the recovery code and multiple PUK values on one printed card. Due to security reasons, this kind of recovery code cannot be used for the recovery operation before the user confirms its physical delivery. To confirm such recovery code, use the following code:

```swift
// 2FA signature with possession factor is required
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

let recoveryCode = "VVVVV-VVVVV-VVVVV-VTFVA" // You can also use code scanned from QR
powerAuthSDK.confirmRecoveryCode(recoveryCode, authentication: auth) { alreadyConfirmed, error in
    if let error = error {
        // Process error
    } else {
        if alreadyConfirmed {
           print("Recovery code has been already confirmed. This is not an error, just information.")
        } else {
           print("Recovery code has been successfully confirmed.")
        }
    }
}
```

The `alreadyConfirmed` boolean indicates that the code was already confirmed in the past. You can choose a different "success" screen, describing that the user has already confirmed such code. Also, note that codes bound to the activations are already confirmed.

## Token-Based Authentication

<!-- begin box warning -->
**WARNING:** Before you start using access tokens, please visit our [documentation for powerauth-crypto](https://github.com/wultra/powerauth-crypto/blob/develop/docs/MAC-Token-Based-Authentication.md) for more information about this feature.
<!-- end -->

The tokens are simple, locally cached objects, producing timestamp-based authorization headers. Be aware that tokens are NOT a replacement for general PowerAuth signatures. They are helpful in situations when the signatures are too heavy or too complicated for implementation. Each token has the following properties:

- It needs a PowerAuth signature for its creation (e.g., you need to provide `PowerAuthAuthentication` object)
- It has a unique identifier on the server. This identifier is not exposed to the public API, but the DEBUG version of SDK can reveal that identifier in the debugger (e.g., you can use `po tokenObject` to print the object's description)
- It has a symbolic name (e.g. "MyToken") defined by the application programmer to identify already created tokens.
- It can generate timestamp-based authorization HTTP headers.
- It can be used concurrently. Token's private data doesn't change over time.
- The token is associated with the `PowerAuthSDK` instance. So, you can use the same symbolic name in multiple SDK instances, and each created token will be unique.
- Tokens are persisted in the keychain and cached in the memory.
- Once the parent `PowerAuthSDK` instance loses its activation, all its tokens are removed from the local database.

### Getting Token

To get an access token, you can use the following code:

```swift
// 1FA signature - uses device-related key
let auth = PowerAuthAuthentication.possession()

let tokenStore = powerAuthSDK.tokenStore

let task = tokenStore.requestAccessToken(withName: "MyToken", authentication: auth) { (token, error) in
    if let token = token {
        // now you can generate a header
    } else {
        // handle error
    }
}
```

The request is performed synchronously or asynchronously depending on whether the token is locally cached on the device. You can test this situation by calling `tokenStore.hasLocalToken(withName: "MyToken")`. If an operation is asynchronous, then `requestAccessToken()` returns a cancellable task.

### Generating Authorization Header

Use the following code to generate an authorization header:

```swift
let task = tokenStore.generateAuthorizationHeader(withName: "MyToken") { header, error in
    if let header = header {
        let httpHeader = [ header.key : header.value ]
        // now you can attach that httpHeader to your HTTP request
    } else {
        // failure, the token is no longer valid, or failed to synchronize time
        // with the server.
    }
}
```

Once you have a `PowerAuthToken` object, then you can use also a synchronous code to generate an authorization header:

```swift
if let header = token.generateHeader() {
    let httpHeader = [ header.key : header.value ]
    // now you can attach that httpHeader to your HTTP request
} else {
    // in case of nil, the token is no longer valid
}
```

<!-- begin box warning -->
The synchronous example above is safe to use only if you're sure that the time is already [synchronized with the server](#synchronized-time).
<!-- end -->


### Removing Token From the Server

To remove the token from the server, you can use the following code:

```swift
let tokenStore = powerAuthSDK.tokenStore
tokenStore.removeAccessToken(withName: "MyToken") { (removed, error) in
    if removed {
        // token has been removed
    } else {
        // handle error
    }
}
```

### Removing Token Locally

To remove the token locally, you can simply use the following code:

```swift
let tokenStore = powerAuthSDK.tokenStore
// Remove just one token
tokenStore.removeLocalToken(withName: "MyToken")
// Remove all local tokens
tokenStore.removeAllLocalTokens()
```

Note that by removing tokens locally, you will lose control of the tokens stored on the server.


## Apple Watch Support

This part of the documentation describes how to add support for Apple Watch to your PowerAuth-powered iOS application. This part of the documentation is not relevant to the **tvOS** platform.

### Prepare Watch Connectivity

The PowerAuth SDK for iOS uses the [WatchConnectivity framework](https://developer.apple.com/documentation/watchconnectivity) to achieve data synchronization between iPhone and Apple Watch devices. If you're not familiar with this framework, take a look at least at [WCSession](https://developer.apple.com/documentation/watchconnectivity/wcsession) and [WCSessionDelegate](https://developer.apple.com/documentation/watchconnectivity/wcsessiondelegate) interfaces before you start.

The PowerAuth SDK doesn't manage the state of the `WCSession` and it doesn't set the delegate to the session's singleton instance. It's up to you to properly configure and activate the default session, but the application has to cooperate with PowerAuth SDK to process the messages received from the counterpart device. To do this, PowerAuth SDKs on both sides are providing the `PowerAuthWCSessionManager` class which can help you process all incoming messages. Here's an example of how you can implement simple `SessionManager` for IOS:

```swift
import Foundation
import WatchConnectivity
import PowerAuth2

class SessionManager: NSObject, WCSessionDelegate {

    static let shared = SessionManager()

    private let session: WCSession? = WCSession.isSupported() ? WCSession.default : nil

    // Returns false, when the session is not available on the device.
    func activateSession() -> Bool {
        session?.delegate = self
        session?.activate()
        return session != nil
    }

    // MARK: - WCSessionDelegate

    func session(_ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: Error?) {
        if activationState == .activated {
            // now you can use WCSession for communication, send the status of the session to watch, etc...
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
        if PowerAuthWCSessionManager.sharedInstance.processReceivedMessageData(messageData, replyHandler: nil) {
            return // processed...
        }
        // Other SDKs or your own messages can be handled here...
        print("SessionManager.didReceiveMessageData did not process message.")
    }

    func session(_ session: WCSession, didReceiveMessageData messageData: Data, replyHandler: @escaping (Data) -> Void) {
        // Try to process PowerAuth messages...
        if PowerAuthWCSessionManager.sharedInstance.processReceivedMessageData(messageData, replyHandler: replyHandler) {
            return // processed...
        }
        // Other SDKs or your own messages can be handled here...
        print("SessionManager.didReceiveMessageData did not process message. Responding with empty data")
        replyHandler(Data())
    }

    func session(_ session: WCSession, didReceiveUserInfo userInfo: [String : Any] = [:]) {
        // Try to process PowerAuth messages...
        if PowerAuthWCSessionManager.sharedInstance.processReceivedUserInfo(userInfo) {
            return // processed...
        }
        // Other SDKs or your own messages can be handled here...
        print("SessionManager.didReceiveUserInfo did not process message.")
    }
}
```

<!-- begin box info -->
The code above is very similar to its [watchOS counterpart](./PowerAuth-SDK-for-watchOS.md#prepare-watch-connectivity).
<!-- end -->

The example is implementing only a minimum set of methods from the `WCSessionDelegate` protocol to make message passing work. The important part is that at some point, both applications (iOS and watchOS) have to call `SessionManager.shared.activateSession()` to make the transfers possible. Once you activate your session on the device, you can use all APIs related to the communication.


### WCSession Activation Sequence

In this chapter, we will discuss the right initialization sequence for various interoperating objects during your application's startup. We recommend following those rules to make communication between iOS & watchOS reliable.

#### Implementation Summary

On the application's startup:

1. Instantiate and configure all `PowerAuthSDK` instances especially ones to be synchronized with Apple Watch.
2. Activate `WCSession`, so get the default instance, assign your delegate, and call `activate()`
3. Wait for the session's activation in your delegate
4. Now you can use watch-related methods from PowerAuth SDK for iOS. For example, you can use a lazy method to send the status of activation to the watch device.

#### Implementation Details

Due to our internal implementation details, each `PowerAuthSDK` instance is registered to `PowerAuthWCSessionManager` for incoming message processing. The registration is done in the object's designated init method, and the de-registration is automatic after the SDK object is destroyed. This technique works great but depends on the existence of the right object at the right time.

Once you activate `WCSession`, your `WCSessionDelegate` is going to receive messages (on the background thread) from the counterpart watch application. We are highlighting the importance of the right activation sequence because your watchOS application can wake up its iOS counterpart. Therefore, it is highly possible that some messages will be available right at the application's startup. If you don't follow the guidelines and forget to prepare your `PowerAuthSDK` instances before the `WCSession` is activated, then a couple of messages may be lost.

Fortunately, the situation on the watchOS side is much easier because all incoming messages are processed in one special service class, which is always available.


### Sending Activation Status to Watch

Before you start using PowerAuth on watchOS, it is recommended to send information about PowerAuth activation from iPhone to Apple Watch. The information transmitted to the watch is very limited. In fact, on the watchOS side, you can check only whether the activation on the iPhone is locally present or not. It is recommended to keep this status up to date as much as possible. That typically means that you may send the status every time you complete or remove the activation.

To send the current status of the activation, use the following code:

```swift
if !powerAuthSDK.sendActivationStatusToWatch() {
    // send message has not been issued, WCSession is probably not available / active
} else {
    // message has been issued and it's guaranteed that it will be delivered to the watch
}
```

There's also an asynchronous version, but the watch device has to be reachable at the time of the call:

```swift
powerAuthSDK.sendActivationStatusToWatch { (error) in
    if let error = error {
        // handle error, otherwise the transfer was OK
    }
}
```

<!-- begin box warning -->
Sending the status of the `PowerAuthSDK` instance that is currently without activation also effectively removes all associated tokens from Apple Watch.
<!-- end -->

### Sending Token to Watch

Once you have a `PowerAuthToken` object, use the following code to send it to the Apple Watch:

```swift
if let token = tokenStore.localToken(withName: "MyToken") {
    if !token.sendToWatch() {
        // send message has not been issued, WCSession is probably not available / active
    } else {
        // message has been issued and it's guaranteed that it will be delivered to the watch
    }
}
```

You can also use a different variant of the method with a completion block. However, you have to be sure that the Apple Watch is reachable at the time of call. Otherwise, the error is returned:

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

You can remotely remove the token from a paired Apple Watch:

```swift
if let token = tokenStore.localToken(withName: "MyToken") {
    if !token.removeFromWatch() {
        // send message has not been issued, WCSession is probably not available / active
    } else {
        // message has been issued and it's guaranteed that it will be delivered to the watch
    }
}
```

There is also an asynchronous version, but the paired watch has to be reachable at the time of the call:

```swift
if let token = tokenStore.localToken(withName: "MyToken") {
    token.removeFromWatch { (error) in
        if let error = error {
            // handle error, otherwise the transfer was OK
        }
    }
}
```

## External Encryption Key

The `PowerAuthSDK` allows you to specify an external encryption key (called EEK in our terminology) that can additionally protect the knowledge and the biometry factor keys. This feature is typically used to create a chain of activations where one instance of `PowerAuthSDK` is primary and unlocks access to all secondary activations.

The external encryption key has to be set before the activation is created, or can be added later. The internal state of `PowerAuthSDK` contains information that the factor keys are protected with EEK, so EEK must be known at the time of PowerAuth signature is calculated. You have three options on how to configure the key:

1. Assign EEK into `externalEncryptionKey` property of `PowerAuthConfiguration` at the time of `PowerAuthSDK` object creation.
   - This is the most convenient way of using EEK, but the key must be known at the time of the `PowerAuthSDK` instantiation.
   - Once the `PowerAuthSDK` instance creates a new activation, then the factor keys will be automatically protected with EEK.
   
2. Use `PowerAuthSDK.setExternalEncryptionKey()` to set EEK after the `PowerAuthSDK` instance is created.
   - This is useful in case EEK is not known during the `PowerAuthSDK` instance creation.
   - You can set the key in any `PowerAuthSDK` state, but be aware that the method will fail in case the instance has a valid activation that doesn't use EEK.
   - It's safe to set the same EEK multiple times.

3. Use `PowerAuthSDK.addExternalEncryptionKey()` to add EEK and protect the factor keys in case `PowerAuthSDK` has already a valid activation.
   - This method is useful in case `PowerAuthSDK` already has a valid activation, but it doesn't use EEK yet.
   - The method automatically adds EEK into the internal configuration structure, but be aware, that all future `PowerAuthSDK` usages (e.g. after app restart) require setting EEK by configuration, or by the `setExternalEncryptionKey()` method.

You can remove EEK from an existing activation if the key is no longer required. To do this, use the `PowerAuthSDK.removeExternalEncryptionKey()` method. Be aware, that EEK must be set by configuration, or by the `setExternalEncryptionKey()` method before you call the remove method. You can also use the `PowerAuthSDK.hasExternalEncryptionKey` property to test whether the key is already set and in use.


## Share Activation Data

This chapter explains how to share the `PowerAuthSDK` activation state between multiple applications from the same vendor, or between application and its extensions. Before you start, you should read [Prepare Data Sharing](PowerAuth-SDK-for-iOS-Extensions.md#prepare-data-sharing) chapter from PowerAuth SDK for iOS Extensions to configure *Keychain Sharing* and *App Groups* in your Xcode project. 

<!-- begin box warning -->
This feature is not supported on the macOS Catalyst platform.
<!-- end -->

### Configure Activation Data Sharing

To share the activation's state just assign an instance of the `PowerAuthSharingConfiguration` object into `PowerAuthConfiguration`:

```swift
// Prepare the configuration
let configuration = PowerAuthConfiguration(
        instanceId: Bundle.main.bundleIdentifier!,
        baseEndpointUrl: "https://localhost:8080/demo-server",
        configuration: "ARDDj6EB6iAUtNm...KKEcBxbnH9bMk8Ju3K1wmjbA==")
// Assign sharing configuration
configuration.sharingConfiguration = PowerAuthSharingConfiguration(
    appGroup: "group.your.app.group", 
    appIdentifier: "com.powerauth.demo.App", 
    keychainAccessGroup: "KTT00000MR.com.powerauth.demo.App")

// Create a PowerAuthSDK instance
let powerAuthSDK = PowerAuthSDK(configuration)
```

The `PowerAuthSharingConfiguration` object contains the following properties:

- `appGroup` is the name of the app group shared between your applications. Be aware, that the length of app group encoded in UTF-8, should not exceed 26 characters. See [troubleshooting](#length-of-application-group) section for more details.
- `appIdentifier` is an identifier unique across your all applications that are supposed to use the shared activation data. You can use your applications' bundle identifiers or any other identifier that can be then processed in all your applications. Due to technical limitations, the length of the identifier must not exceed 127 bytes, if represented in UTF-8.
- `keychainAccessGroup` is an access group for keychain sharing.

Unlike the regular configuration the `instanceId` value in `PowerAuthConfiguration` should not be based on the application's bundle identifier. This is because all your applications must use the same identifier, so it's recommended to use some predefined constant string.


### External pending operations

Some operations, such as the activation process, must be exclusively finished in the application that initiated the operation. For example, if you start an activation process in one app, then all other applications that use the same shared activation data may receive a failure with the `PowerAuthErrorCode.externalPendingOperation` error code until the operation is finished. To prevent such errors you can determine this state in advance:

```swift
if let externalOperation = powerAuthSDK.externalPendingOperation {
    print("Application \(externalOperation.externalApplicationId) already started \(externalOperation.externalOperationType)")
}
```

The same `PowerAuthExternalPendingOperation` object can be also extracted from the `NSError` error. For example:

```swift
powerAuthSDK.createActivation(activation) { (result, error) in
    if let error = error {
        if let externalOperation = error.powerAuthExternalPendingOperation {
            print("Application \(externalOperation.externalApplicationId) already started \(externalOperation.externalOperationType)")
        }
    }
}
``` 

## Synchronized Time

The PowerAuth mobile SDK internally uses time synchronized with the PowerAuth Server for its cryptographic functions, such as [End-To-End Encryption](#end-to-end-encryption) or [Token-Based Authentication](#token-based-authentication). The synchronized time can also be beneficial for your application. For example, if you want to display a time-sensitive message or countdown to your users, you can take advantage of this service.

Use the following code to get the service responsible for the time synchronization: 

```swift
let timeService = powerAuthSDK.timeSynchronizationService
```

### Automatic Time Synchronization

The time is synchronized automatically in the following situations:

- After an activation is created
- After getting an activation status
- After receiving any response encrypted with our End-To-End Encryption scheme

The time synchronization is reset automatically once your application transitions from the background to the foreground.

### Manually Synchronize Time

Use the following code to synchronize the time manually:

```swift
let task = timeService.synchronizeTime(callback: { error in
    if error == nil {
        // Success, time has been properly synchronized
    } else {
        // Failed to synchronize the time
    }
}, callbackQueue: .main)
```

### Get Synchronized Time

To get the synchronized time, use the following code:

```swift
if timeService.isTimeSynchronized {
    // Get synchronized timestamp
    let timestamp = timeService.currentTime()
    // If a date object is required, then use the following snippet
    let date = Date(timeIntervalSince1970: timestamp)
} else {
    // Time is not synchronized yet. If you call currentTime() then 
    // the returned timestamp is similar to Date().timeIntervalSince1970
    let timestamp = timeService.currentTime()
}
```

The time service provides additional information about time, such as how precisely the time is synchronized with the server:

```swift
if timeService.isTimeSynchronized {
    let precision = timeService.localTimeAdjustmentPrecision
    print("Time is synchronized with precision \(precision)")
}
```

The precision value represents a maximum absolute deviation of synchronized time against the actual time on the server. For example, a value `0.5` means that the time provided by the `currentTime()` method maybe 0.5 seconds ahead or behind the actual time on the server. If the precision is not sufficient for your purpose, for example, if you need to display a real-time countdown in your application, then try to synchronize the time manually. The precision basically depends on how quickly is the synchronization response received and processed from the server. A faster response results in higher precision.

## Common SDK Tasks

### Error Handling

Most of the SDK methods return an error object of an `NSError` class in case something goes wrong. Of course, it is your responsibility to handle the errors these objects represent. There are two ways how you can obtain an error object from PowerAuth SDK for iOS.

In most cases, you receive an error object via a callback, like in this example:

```swift
powerAuthSDK.fetchActivationStatus { (status, error) in
    // Handle 'error' here
}
```

In other cases, you receive an error via an exception, like in this example:

```swift
do {
    try powerAuthSDK.persistActivation(withPassword: "1234")
} catch let error as NSError {
    // Handle 'error' here
}
```

<!-- begin box info -->
The original Objective-C code uses a method with the `BOOL` return type that passes `NSError**` (pointer to error object) as a method parameter. This syntax is automatically converted to exceptions when using code in Swift.
<!-- end -->

Errors that are caused by PowerAuth SDK for iOS use the `PowerAuthErrorDomain` and `PowerAuthErrorCode` enumeration available via the `NSError.powerAuthErrorCode` property. Use these values to determine the type of error. In principle, all errors should be handled in a very similar manner. Use this code snippet for inspiration:

```swift
if error == nil {
    // No error happened
} else {
    // Handle the error
    if let error = error as NSError? {

        // If yes, handle the error based on the error code
        switch error.powerAuthErrorCode {
        
        case .NA:
            print("Error has different domain than PowerAuthErrorDomain")
            
        case .networkError:
            print("Error code for error with network connectivity or download")

        case .signatureError:
            print("Error code for error in signature calculation")

        case .invalidActivationState:
            print("Error code for error that occurs when activation state is invalid")
        
        case .invalidActivationCode:
            print("Error code for error that occurs when activation or recovery code is invalid")
            
        case .invalidActivationData:
            print("Error code for error that occurs when activation data is invalid")

        case .missingActivation:
            print("Error code for error that occurs when activation is required but missing")

        case .activationPending:
            print("Error code for error that occurs when pending activation is present and work with completed activation is required")

        case .biometryNotAvailable:
            print("Error code for TouchID/FaceID not available error")

        case .biometryCancel:
            print("Error code for TouchID/FaceID action cancel error")
        
        case .biometryFallback:
            print("Error code for TouchID/FaceID fallback action")
            
        case .biometryFailed:
            print("Error code for TouchID/FaceID action failure")

        case .operationCancelled:
            print("Error code for cancelled operations")

        case .encryption:
            print("Error code for errors related to end-to-end encryption")
            
        case .wrongParameter:
            print("Error code for general API misuse")

        case .invalidToken:
            print("Error code for errors related to token based auth.")

        case .watchConnectivity:
            print("Error code for errors related to synchronization between iOS and watchOS.")

        case .protocolUpgrade:
            print("Error code for error that occurs when protocol upgrade fails at unrecoverable error.")

        case .pendingProtocolUpgrade:
            print("The operation is temporarily unavailable, due to pending protocol upgrade.")

        case .externalPendingOperation:
            print("Other application is doing activation or protocol upgrade.")
            
        case .timeSynchronization:
            print("Failed to synchronize time with the server.")
            
        default:
            print("Unknown error")
        }
    }
}
```

Note that you typically don't need to handle all error codes reported in the `Error` object, or report all those situations to the user. Most of the codes are informational and help the developers properly integrate SDK into the application. A good example is `PowerAuthErrorCode.invalidActivationState`, which typically means that your application's logic is broken and you're using PowerAuthSDK in an unexpected way.

Here's the list of important error codes, which the application should properly handle:

- `PowerAuthErrorCode.biometryCancel` is reported when the user cancels the biometric authentication dialog
- `PowerAuthErrorCode.biometryFallback` is reported when the user cancels the biometric authentication dialog with a fallback button
- `PowerAuthErrorCode.protocolUpgrade` is reported when SDK fails to upgrade itself to a newer protocol version. The code may be reported from `PowerAuthSDK.fetchActivationStatus()`. This is an unrecoverable error resulting in the broken activation on the device, so the best situation is to inform the user about the situation and remove the activation locally.
- `PowerAuthErrorCode.pendingProtocolUpgrade` is reported when the requested SDK operation cannot be completed due to a pending PowerAuth protocol upgrade. You can retry the operation later. The code is typically reported in situations when SDK is performing protocol upgrade in the background (as a part of activation status fetch), and the application wants to calculate the PowerAuth signature in parallel operation. Such kind of concurrency is forbidden since SDK version `1.0.0`
- `PowerAuthErrorCode.externalPendingOperation` is reported when the requested operation collides with the same operation type already started in the external application.

### Working with Invalid SSL Certificates

Sometimes, you may need to develop or test your application against a service that runs over HTTPS protocol with an invalid (self-signed) SSL certificate. By default, the HTTP client used in PowerAuth SDK communication validates the certificate. To disable the certificate validation, add the following code just before your `PowerAuthSDK` instance configuration:

```swift
// Set `PowerAuthClientSslNoValidationStrategy as the default client SSL certificate validation strategy`
PowerAuthClientConfiguration.sharedInstance().sslValidationStrategy = PowerAuthClientSslNoValidationStrategy()

// In case you're setting the `PowerAuthClientConfiguration` explicitly, use:
let clientConfig = PowerAuthClientConfiguration()
clientConfig.sslValidationStrategy = PowerAuthClientSslNoValidationStrategy()
// configure the PowerAuthSDK object
let powerAuthSDK = PowerAuthSDK(
    configuration: PowerAuthConfiguration(...),
    keychainConfiguration: nil, // optional, default will be used when nil
    clientConfiguration: clientConfig
)
```

### Debugging

The debug log is by default turned off. To turn it on, use the following code:

```swift
PowerAuthLogSetEnabled(true)
```

To turn on an even more detailed log, use the following code:

```swift
PowerAuthLogSetVerbose(true)
```

<!-- begin box warning -->
Note that the functions above are effective only if PowerAuth SDK is compiled in the `DEBUG` build configuration or `ENABLE_PA2_LOG` compilation flag is set.
<!-- end -->

You can intercept the log and log it into your own report system, you can do so with `PowerAuthLogDelegate`.

```swift
import PowerAuth2

class MyClass: PowerAuthLogDelegate {

    init {
        // Only works in DEBUG build or when 
        // ENABLE_PA2_LOG compilation flag is set
        PowerAuthLogSetEnabled(true)
        #if DEBUG
        // verbose logging should be used only in debug builds
        // as it can contain sensitive information
        PowerAuthLogSetVerbose(true)
        #endif
        PowerAuthLogSetDelegate(self)
    }
    
    // MARK: - PowerAuthLogDelegate implementation
    
    func powerAuthLog(_ log: String) {
        // Process the log...
    }
}
```

## Additional Features

PowerAuth SDK for iOS contains multiple additional features that are useful for mobile apps.

### Obtaining User's Claims

If supported by the server, the PowerAuth mobile SDK can provide additional information asserted about a person associated with an activation. This information can be obtained either during the activation process or at a later time.

Here is an example of how to process user information during activation:

```swift
powerAuthSDK.createActivation(activation) { (result, error) in
    if let result {
        if let userInfo = result.userInfo {
            // User information received.
            // At this moment, the object is also available at
            // powerAuthSDK.lastFetchedUserInfo
        }
    } else {
        // Error handling
    }
}
```

To fetch the user information at a later time, use the following code:

```swift
if let userInfo = powerAuthSDK.lastFetchedUserInfo {
    // User information is already available
} else {
    sdk.fetchUserInfo { userInfo, error in
        if let userInfo {
            // User information received
        } else {
            // Error handling
        }
    }
}
```

The obtained `PowerAuthUserInfo` object contains the following properties:

| Property                | Type     | Description |
|-------------------------|----------|-------------|
| `subject`               | `String` | The user's identifier |
| `name`                  | `String` | The full name of the user |
| `givenName`             | `String` | The given or first name of the user |
| `familyName`            | `String` | The surname(s) or last name(s) of the user |
| `middleName`            | `String` | The middle name of the user |
| `nickname`              | `String` | The casual name of the user |
| `preferredUsername`     | `String` | The username by which the user wants to be referred to at the application |
| `profileUrl`            | `String` | The URL of the profile page for the user |
| `pictureUrl`            | `String` | The URL of the profile picture for the user |
| `websiteUrl`            | `String` | The URL of the user's web page or blog |
| `email`                 | `String` | The user's preferred email address |
| `isEmailVerified`       | `Bool`   | True if the user's email address has been verified, else false<sup>1</sup> |
| `phoneNumber`           | `String` | The user's preferred telephone number<sup>2</sup> |
| `isPhoneNumberVerified` | `Bool`   | True if the user's telephone number has been verified, else false<sup>1</sup> |
| `gender`                | `String` | The user's gender |
| `birthdate`             | `Date`   | The user's birthday |
| `zoneInfo`              | `String` | The user's time zone, e.g. `Europe/Paris` or `America/Los_Angeles` |
| `locale`                | `String` | The end-users locale, represented as a BCP47 language tag<sup>3</sup> |
| `address`               | `PowerAuthUserAddress` | The user's preferred postal address |
| `updatedAt`             | `Date`   | The time the user's information was last updated |
| `allClaims`             | `[String : Any]` | The full collection of standard claims received from the server |

If the `address` is provided, then `PowerAuthUserAddress` contains the following properties:

| Property                | Type     | Description |
|-------------------------|----------|-------------|
| `formatted`             | `String` | The full mailing address, with multiple lines if necessary |
| `street`                | `String` | The street address component, which may include house number, street name, post office box, and other multi-line information |
| `locality`              | `String` | City or locality component |
| `region`                | `String` | State, province, prefecture or region component |
| `postalCode`            | `String` | Zip code or postal code component |
| `country`               | `String` | Country name component |
| `allClaims`             | `[String : Any]` | Full collection of standard claims received from the server |

> Notes:
> 1. Value is false also when the claim is not present in the `allClaims` dictionary
> 2. Phone number is typically in E.164 format, for example `+1 (425) 555-1212` or `+56 (2) 687 2400`
> 3. This is typically an ISO 639-1 Alpha-2 language code in lowercase and an ISO 3166-1 Alpha-2 country code in uppercase, separated by a dash. For example, `en-US` or `fr-CA`

<!-- begin box info -->
Be aware that all properties in the `PowerAuthUserInfo` and `PowerAuthUserAddress` objects are optional and the availability of information depends on actual implementation on the server.
<!-- end -->

### Password Strength Indicator

Choosing a weak passphrase in applications with high-security demands can be potentially dangerous. You can use our [Wultra Passphrase Meter](https://github.com/wultra/passphrase-meter) library to estimate the strength of the passphrase and warn the user when he tries to use such a passphrase in your application.

### Debug Build Detection

It is sometimes useful to switch PowerAuth SDK to a DEBUG build configuration to get more logs from the library:

- **CocoaPods:** A majority of the SDK is distributed as source codes, so it will match your application's build configuration. Only low-level C++ codes and several wrapper classes on top of those are precompiled into a static library.
- **Manual installation:** Xcode matches build configuration across all nested projects, so you usually don't need to care about the configuration switching.

The DEBUG build is usually helpful during application development, but on the other hand, it's highly unwanted in production applications. For this purpose, the `PowerAuthSystem.isInDebug()` method provides information on whether the PowerAuth library was compiled in DEBUG configuration. It is a good practice to check this flag and crash the process when the production application is linked against the DEBUG PowerAuth:

```swift
#if YOUR_APPSTORE_BUILD_FLAG
    // Final vs Debug library trap
    if PowerAuthSystem.isInDebug() {
        fatalError("CRITICAL ERROR: You're using Debug PowerAuth library in production build.")
    }
#endif
```

### Request Interceptors

The `PowerAuthClientConfiguration` can contain multiple request interceptor objects, allowing you to adjust all HTTP requests created by the SDK before their execution. Currently, you can use the following two classes:

- `PowerAuthBasicHttpAuthenticationRequestInterceptor` to add a basic HTTP authentication header to all requests
- `PowerAuthCustomHeaderRequestInterceptor` to add a custom HTTP header to all requests

For example:

```swift
let basicAuth = PowerAuthBasicHttpAuthenticationRequestInterceptor(username: "gateway-user", password: "gateway-password")
let customHeader = PowerAuthCustomHeaderRequestInterceptor(headerKey: "X-CustomHeader", value: "123456")
let clientConfig = PowerAuthClientConfiguration()
clientConfig.requestInterceptors = [ basicAuth, customHeader ]
```

We don't recommend implementing the `PowerAuthHttpRequestInterceptor` protocol on your own. The interface allows you to tweak the requests created in the `PowerAuthSDK` but also gives you an opportunity to break things. So, rather than create your own interceptor, contact us and describe what use case is missing. Also, keep in mind that the interface may change in the future. We can guarantee the API stability of public classes implementing this interface, but not the stability of the interface itself.

### Custom User-Agent

The `PowerAuthClientConfiguration` contains the `userAgent` property that allows you to set a custom value for the "User-Agent" HTTP request header for all requests initiated by the library:

```swift
let clientConfig = PowerAuthClientConfiguration()
clientConfig.userAgent = "MyClient/1.0.0"
```

The default value of the property is composed as "APP-EXECUTABLE/APP-VERSION PowerAuth2/PA-VERSION (OS/OS-VERSION, DEVICE-INFO)", for example: "MyApp/1.0 PowerAuth2/1.7.0 (iOS 15.2, iPhone12.1)". The information about the application executable and version is obtained from the main bundle and its `Info.plist`.

If you set `nil` to the `userAgent` property, then the default "User-Agent" provided by the operating system will be used. 


## Troubleshooting

### tvOS support in CocoaPods

The tvOS SDK is not required by default since the SDK version 1.7.7. If your build or development machine doesn't have tvOS SDK installed, then the `PowerAuthCore` module is precompiled with no tvOS platform included in the final xcframework. Since CocoaPods keep various build artifacts in its cache, then this might be problematic in case you'll add support for tvOS later, during the development. To fix such possible issues, please remove the `PowerAuthCore` pod from the cache:

```sh
pod cache clean 'PowerAuthCore' --all
```

### Length of application group

In case you use the [Activation data sharing](#share-activation-data) feature, the length of the application group encoded in UTF-8 must not exceed **26 characters**. This limitation exists because the feature relies on named shared memory objects, and iOS imposes an undocumented restriction on the length of such object names.

The total length is limited to 31 characters, but the shared memory object name must be prefixed with your app group, separated by a period (.), to function properly across your applications. We chose to use a 4-character long shared memory object name, generated from the PowerAuthSDK’s instance identifier. As a result, the actual limit for your app group name is:

```
31 - 1 - 4 = 26
```

You can extend the length of the application group slightly by providing your own `sharedMemoryIdentifier` in the `PowerAuthSharingConfiguration`. In theory, this allows you to use an app group name of up to 29 characters, leaving 1 character for the shared memory identifier. However, this is generally not recommended. A custom identifier should only be used if your application already employs shared memory and the SDK’s generated identifier conflicts with your existing shared memory objects.
