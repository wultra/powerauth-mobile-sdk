# PowerAuth Mobile SDK for iOS and tvOS Apps

<!-- begin remove -->
## Table of Contents

- [Installation](#installation)
  - [Supported Platforms](#supported-platforms)
  - [CocoaPods Installation](#cocoapods)
- [Post-Installation Steps](#post-installation-steps)
  - [Include PowerAuth SDK in Your Sources](#include-powerauth-sdk-in-your-sources)
- [SDK Configuration](#configuration)
- [Device Activation](#activation)
  - [Activation via Activation Code](#activation-via-activation-code)
  - [Activation via OpenID Connect](#activation-via-openid-connect)
  - [Activation via Custom Credentials](#activation-via-custom-credentials)
  - [Customize Activation](#customize-activation)
  - [Persisting Activation Data](#persisting-activation-data)
  - [Validating User Inputs](#validating-user-inputs)
- [Requesting Device Activation Status](#requesting-activation-status)
- [Data Signing](#data-signing)
- [Authentication Codes](#authentication-codes)
  - [Symmetric Multi-Factor Authentication Code](#symmetric-multi-factor-authentication-code)
  - [Symmetric Offline Multi-Factor Authentication Code](#symmetric-offline-multi-factor-authentication-code)
- [Digital Signatures](#digital-signatures)
  - [Asymmetric Private Key Signature](#asymmetric-private-key-signature)
  - [Producing Signed JWT with Provided Claims](#producing-signed-jwt-with-provided-claims)
  - [Verify Server-Signed Data](#verify-server-signed-data)
  - [Verify JSON Web Signature](#verify-json-web-signature)
  - [Creating Certificate Signing Request](#creating-certificate-signing-request)
  - [Getting Device Public Keys](#getting-device-public-keys)
- [Password Change](#password-change)
- [Working with passwords securely](#working-with-passwords-securely)
- [Working with sensitive data](#working-with-sensitive-data)
- [Biometry Setup](#biometry-setup)
- [Biometry Troubleshooting](#biometry-troubleshooting)
- [Device Activation Removal](#activation-removal)
- [End-To-End Encryption](#end-to-end-encryption)
- [Secure Vault](#secure-vault)
- [Token-Based Authentication](#token-based-authentication)
- [Authenticated Protocol Upgrade](#authenticated-protocol-upgrade)
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

- [PowerAuth SDK for watchOS](./PowerAuth-SDK-for-watchOS.md)
<!-- end -->

## Installation

This chapter describes how to get PowerAuth SDK for iOS and tvOS up and running in your app. In the current version, you can choose between CocoaPods and Swift Package Manager library integration.

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

If you wish to integrate the PowerAuth SDK into your app via SPM, please visit the [PowerAuth mobile SDK for Swift PM](https://github.com/wultra/powerauth-mobile-sdk-spm)


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

To sum it up, in order to configure the `PowerAuthSDK` instance, add the following code to your application delegate:

```swift
func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplicationLaunchOptionsKey: Any]?) -> Bool {

    // Prepare the configuration
    let configuration = PowerAuthConfiguration(
        instanceId: Bundle.main.bundleIdentifier!,
        baseEndpointUrl: "https://<your-domain>/enrollment-server",
        configuration: "ARDDj6EB6iAUtNm...KKEcBxbnH9bMk8Ju3K1wmjbA==")
    do {
        // Create a PowerAuthSDK instance with the configuration
        let powerAuth = try PowerAuthSDK(configuration: configuration)
    } catch let err as NSError {
        switch err.powerAuthErrorCode {
        case .wrongParameter:
            // Invalid configuration.
        case .invalidActivationData:
            // Unrecognized data format. You can log this event, clear data and retry SDK construction
            try PowerAuthSDK.cleanupInstanceData(configuration: configuration)
        case .upgradeSDK:
            // Upgrade SDK in your application
        default:
            // other errors
            break
        }
    }
}
```

### Additional configuration

The `PowerAuthConfiguration` has the following additional properties:

- `algorithm` - Alters [algorithm](#algorithms-for-communication) used for the communication with the PowerAuth Server.
- `offlineAuthenticationCodeComponentLength` - Alters the default component length for the [offline authentication code](#symmetric-offline-multi-factor-authentication-code). The values between 4 and 8 are allowed. The default value is 8.
- `keychainKey_Biometry` - Specifies the 'key' used to store the `PowerAuthSDK` instance’s biometry-related key in the biometry keychain. If not set, the `instanceId` is applied. Do not alter this configuration unless you have a valid reason to do so.

### Biometric configuration

The `PowerAuthBiometricConfiguration` object configures biometric authentication in the `PowerAuthSDK` object. It has the following configuration properties:

- `invalidateBiometricFactorAfterChange` - If set to `true`, the biometric factor is invalidated when fingers are added or removed for Touch ID, or when the user re-enrolls for Face ID. The default value is false (i.e., changing biometric settings in the system does not invalidate the biometric factor).
- `allowFallbackToDevicePasscode` -  If set to `true`, an item protected with biometry can also be accessed using the device passcode. If enabled, the `invalidateBiometricFactorAfterChange` option has no effect. The default value is `false`, meaning fallback to the device passcode is not enabled.
- `invalidateLocalAuthenticationContextAfterUse` - If set to `true`, the `LAContext` object provided by the application is invalidated after use in the SDK. The default value is true, meaning `LAContext` cannot be reused for retrieving keys protected with biometry.

### HTTP client configuration

The `PowerAuthClientConfiguration` object contains configuration for a HTTP client used internally by `PowerAuthSDK` object. It has the following configuration properties:

- `defaultRequestTimeout` - Property that specifies the default HTTP client request timeout. The default value is 20.0 seconds.
- `sslValidationStrategy` - Property that specifies the SSL validation strategy applied by the client. The default value is the default `URLSession` behavior. See [Working with Invalid SSL Certificates](#working-with-invalid-ssl-certificates) chapter for more details.
- `requestInterceptors`- Property that specifies the list of [request interceptors](#request-interceptors) used by the client before the request is executed. The default value is `nil`.
- `userAgent` -  Property that specifies the content of User-Agent request header. The default is value calculated in `PowerAuthSystem.defaultUserAgent()` function. If you set `nil` to this property, then the default value provided by operating system is used.

### Keychain configuration

The `PowerAuthKeychainConfiguration` object contains configuration for a keychain-based storage used by `PowerAuthSDK` class internally.

<!-- begin box warning -->
We strongly discourage you from altering the properties in this configuration unless you know what you are doing.
<!-- end -->

The configuration contains the following properties:

- `keychainInstanceName_Status` - Property that specifies the name of the Keychain service used to store statuses for different PowerAuth instances. You should not change this property unless you have a valid reason to do so.
- `keychainInstanceName_Possession` - Property that specifies the name of the Keychain service used to store possession factor related key (one value for all `PowerAuthSDK` instances).
- `keychainInstanceName_Biometry` - Property that specifies the name of the Keychain service used to store biometry related keys for different `PowerAuthSDK` instances.
- `keychainInstanceName_TokenStore` - Property that specifies the name of the Keychain service used to store content of `PowerAuthToken` objects.
- `keychainKey_Possession` - Property that specifies a storage key used to store possession factor related key in an associated possession Keychain service.

The following properties are defined, but deprecated:

- `keychainAttribute_AccessGroup` - Property that specifies a keychain access group in case that keychain is shared between multiple applications or between application and its extensions. Use configuration for [Activation Data Sharing](#configure-activation-data-sharing) instead.
- `keychainAttribute_UserDefaultsSuiteName` - Property that specifies the name of `UserDefaults` suite to store the flag indicating that application has been re-installed. If the value is not provided, then `UserDefaults.standardUserDefaults` suite is used. Use configuration for [Activation Data Sharing](#configure-activation-data-sharing) instead.
- `linkBiometricItemsToCurrentSet` - If set, then the item protected with the biometry is invalidated if fingers are added or removed for Touch ID, or if the user re-enrolls for Face ID. The default value is `false` (e.g. changing biometry in the system doesn't invalidate the entry). Use `PowerAuthBiometricConfiguration.invalidateBiometricFactorAfterChange` instead.
- `allowBiometricAuthenticationFallbackToDevicePasscode` - If set to `true`, then the item protected with the biometry can be accessed also with a device passcode. If set, then `linkBiometricItemsToCurrentSet` option has no effect. The default is `false`, so fallback to device's passcode is not enabled. Use `PowerAuthBiometricConfiguration.allowFallbackToDevicePasscode` instead.
- `invalidateLocalAuthenticationContextAfterUse` - If set to `true`, then the `LAContext` object provided by application is invalidated after the use in SDK. The default value is `true`, so `LAContext` cannot be reused for getting keys protected with biometry. Use `PowerAuthBiometricConfiguration.invalidateLocalAuthenticationContextAfterUse` instead.


### Algorithms for Communication

The PowerAuth Mobile SDK supports multiple algorithms for communication with the **PowerAuth Server**. Each algorithm has unique properties, allowing you to choose whether to prioritize security, performance, or a balance of both.

The following algorithms are currently supported:

- `EC_P384_ML_L3` — **default algorithm**  
  - Provides the best balance between performance and security, including post-quantum resistance.  
  - Uses a **hybrid** scheme combining P-384–based ECC with ML-KEM-768 and ML-DSA-65 algorithms.  
  - Requires PowerAuth Server **2.0 or later**.

- `EC_P384_ML_L5`
  - Provides the highest level of security, including post-quantum resistance.  
  - Uses a **hybrid** scheme combining P-384–based ECC with ML-KEM-1024 and ML-DSA-87 algorithms.  
  - Requires PowerAuth Server **2.0 or later**.

- `EC_P384`
  - Offers excellent performance and stronger security than the legacy protocol V3.3, but is not quantum-resistant.  
  - This algorithm is based on P-384 ECC and should be used only if your infrastructure cannot yet handle the higher load introduced by post-quantum algorithms.  
  - Requires PowerAuth Server **2.0 or later**.

- `LEGACY_P256`
  - Based on P-256 ECC and fully compatible with PowerAuth protocol V3.3.  
  - Intended to help you migrate your application code to the API changes introduced in PowerAuth Mobile SDK 2.0 while maintaining compatibility with your existing infrastructure. Once your PowerAuth Server is upgraded to version 2.0 or later, you should switch to at least `EC_P384`.  
  - Requires PowerAuth Server **1.9 or later**.

<!-- begin box info -->
If you select `LEGACY_P256` algorithm, then SDK may behave slightly different in some rare cases. The rest of the documentation will use **"legacy mode"** or **"legacy activation"** terminology to highlight such situation.
<!-- end -->

The default algorithm can be overridden by specifying a different one in the SDK configuration:

```swift
// Prepare the configuration
let configuration = PowerAuthConfiguration(
    instanceId: Bundle.main.bundleIdentifier!,
    baseEndpointUrl: "https://<your-domain>/enrollment-server",
    configuration: "ARDDj6EB6iAUtNm...KKEcBxbnH9bMk8Ju3K1wmjbA==",
    algorithm: .EC_P384_ML_L5)

// Create a PowerAuthSDK instance with the configuration
let powerAuth = try PowerAuthSDK(configuration: configuration)
```

The selected algorithm cannot be changed after a `PowerAuthSDK` instance is created, but it can be updated across the lifetime of your application. If the selected algorithm does not match the one used for the activation currently present on the device, the [authenticated protocol upgrade](#authenticated-protocol-upgrade) process must be performed to switch to the new algorithm.

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
    } else {
        // Error occurred, report it to the user
    }
}
```

<!-- begin box warning -->
Note that if you use `UIDevice.current.name` for a device’s name, your application must include an [appropriate entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_developer_device-information_user-assigned-device-name); otherwise, the operating system will provide a generic `iPhone` string.
<!-- end -->

#### Additional Activation OTP

If an [additional activation OTP](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Advanced-Activation-Flows.md#additional-user-authentication-using-activation-otp) is required to complete the activation, then use the following code to configure the `PowerAuthActivation` object:

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
Be aware that OTP can be used only if the activation is configured for ON_KEY_EXCHANGE validation on the PowerAuth server. See our [crypto documentation for details](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Advanced-Activation-Flows.md#regular-activation-with-otp).
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
sdk.persistActivation(withPassword: "1234") { error in
    if let error {
        // process failure
    }
}
```

This code has created activation with two factors: possession (key stored using a key derived from a device fingerprint) and knowledge (password, in our case, a simple PIN code). If you would like to enable Touch or Face ID support at this moment, use the following code instead of the one above:

```swift
let auth = PowerAuthAuthentication.persistWithPasswordAndBiometry(password: "1234")
sdk.persistActivation(with: auth) { error in
    if let error {
        // process error
    }
}
```


### Validating User Inputs

The mobile SDK provides a couple of functions in the `PowerAuthActivationCodeUtil` interface, helping with user input validation. You can:

- Parse activation code when it's scanned from QR code
- Validate a whole code at once
- Auto-correct characters typed on the fly

#### Validating Scanned QR Code

To validate an activation code scanned from the QR code, you can use the `PowerAuthActivationCodeUtil.parse(fromActivationCode:)` function. You have to provide the code with or without the signature part. For example:

```swift
let scannedCode = scannedCode = "VVVVV-VVVVV-VVVVV-VTFVA#MEYCIQD4cqcWloM9PFcdgKemMH4fvXvZhYtm0HU2VI/pCFII8AIhAKGAC3YKjtS0aH99A71JBv27BR7p7gJf+EFsmsGlX5qm"
guard let parsed = PowerAuthActivationCodeUtil.parse(fromActivationCode: scannedCode) else {
    // Invalid code
    return
}
// Extract activation code
let activationCode = parsed.activationCode
```

The previous versions of PowerAuth Mobile SDK (older than 2.0) allowed you to verify the signature part extracted from a scanned QR code. This is no longer possible due to the fact that PQC signatures are too big to be embedded in a QR code. If the activation code with a signature is used in the activation process, then the signature part is ignored. You can still use `PowerAuthActivationCodeUtil` class to parse the scanned code and strip the signature part from it as the example above shows.

#### Validating Entered Activation Code

To validate an activation code at once, you can call the `PowerAuthActivationCodeUtil.validateActivationCode()` function. You have to provide the code without the signature part. For example:

```swift
let isValid   = PowerAuthActivationCodeUtil.validateActivationCode("VVVVV-VVVVV-VVVVV-VTFVA")
let isInvalid = PowerAuthActivationCodeUtil.validateActivationCode("VVVVV-VVVVV-VVVVV-VTFVA#aGVsbG8gd29ybGQ=")
```

If your application is using your own validation, then you should switch to functions provided by SDK. The reason for that is that since SDK `1.0.0`, all activation codes contain a checksum, so it's possible to detect mistyped characters before you start the activation. Check our [Activation Code](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Activation-Code.md) documentation for more details.

#### Auto-Correcting Typed Characters

You can implement auto-correcting of typed characters by using the `PowerAuthActivationCodeUtil.validateAndCorrectTypedCharacter()` function on screens, where the user is supposed to enter an activation code. This technique is possible because Base32 is constructed so that it doesn't contain visually confusing characters. For example, `1` (number one) and `I` (capital I) are confusing, so only `I` is allowed. The benefit is that the provided function can correct typed `1` and translate it to `I`.

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
            if status.isProtocolUpgradeAvailable {
                // Upgrade to new protocol version is available
            }

        } else {
            // Network error occurred, report it to the user
        }
    }

} else {
    // No activation present on the device
}
```

### Activation states

This chapter explains activation states in detail. To get more information about activation lifecycle, check the [Activation States](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Activation.md#activation-states) chapter available in our [powerauth-crypto](https://github.com/wultra/powerauth-crypto) repository.

#### `PowerAuthActivationState.pendingCommit`

The activation record is created, and the key exchange between the client and server has already taken place, but the activation record on the server requires additional approval before it can be used. This approval is typically performed through an internet banking platform by the client or handled by an authorized representative in a back office system.

#### `PowerAuthActivationState.active`

The activation record is created and active. It is ready to be used for typical use-cases, such as generating authentication codes.

#### `PowerAuthActivationState.blocked` 

The activation record is blocked and cannot be used for most use-cases, such as generating authentication codes. While it can be unblocked and activated again, the unblock process cannot be performed locally on the mobile device and requires intervention through an external system, such as internet banking or a back office platform.

#### `PowerAuthActivationState.removed`

The activation record is removed and permanently blocked. It cannot be used for generating authentication codes or ever unblocked. You can inform user about this situation and remove the activation locally.

#### `PowerAuthActivationState.deadlock` 

The local activation is technically blocked and can no longer be used for authentication code calculations. You can inform the user about this situation and remove the activation locally.

The reason why the mobile client is no longer capable of calculating valid authentication codes is that the logical counter is out of sync between the client and the server. This may happen only if the mobile client calculates too many PowerAuth authentication codes without subsequent validation on the server. For example:

- If your application repeatedly constructs HTTP requests with a PowerAuth authentication code while the network is unreachable.
- If your application repeatedly creates authentication tokens while the network is unreachable. For example, when trying to register for push notifications in the background, without user interaction.
- If you calculate too many offline authentication codes without subsequent validation.

In rare situations, this may also happen in development or testing environments, where you’re able to restore the state of the activation on the server from a snapshot.


## Data Signing

The main feature of the PowerAuth protocol is data signing. PowerAuth has the following types of signatures:

- [Symmetric Multi-Factor Authentication Code](#symmetric-multi-factor-authentication-code): Suitable for most operations, such as login, new payment, or confirming changes in settings.
- [Symmetric Offline Multi-Factor authentication Code](#symmetric-offline-multi-factor-authentication-code): Suitable for very secure operations, where the authentication code is validated over the out-of-band channel.
- [Asymmetric Private Key Signature](#sign-data-with-device-private-key): Suitable for documents where a strong one-sided signature is desired.
- [Verify server signed data](#verify-server-signed-data): Suitable for receiving arbitrary data from the server.

## Authentication Codes

### Symmetric Multi-Factor Authentication Code

This type of data authentication is suitable for online operations, such as login, new payment, or confirming changes in settings, and allows you to sign data in HTTP request.

To sign request data, you need to first obtain user credentials (password, PIN code, Touch ID scan) from the user. The task of obtaining the user credentials is used in more use cases covered by the SDK. The core class is `PowerAuthAuthentication` that holds information about the used authentication factors:

```swift
// 1FA authentication code - uses device-related key only.
let oneFactor = PowerAuthAuthentication.possession()

// 2FA authentication code - uses device-related key and user PIN code.
let twoFactorPassword = PowerAuthAuthentication.possessionWithPassword(password: "1234")

// 2FA authentication code - uses biometry factor-related key as a 2nd. factor.
let task = powerAuthSDK.authenticateUsingBiometry(withPrompt: "Please authenticate with biometry to log-in.") { authentication, error in
    if let authentication {
        // the returned authentication object is ready to use for the authentication code calculation
    } else {
        // Failure, cast object to NSError
        guard let error = error as? NSError else {
            fatalError() // Should never happen
        }
        if error.powerAuthErrorCode == .biometryCancel {
            // user canceled the operation
        } else {
            // other errors...
        }
    }
}
// In case the biometric authentication is no longer relevant (for example, you have a limited time to complete the operation), 
// then you can cancel the returned task.
task.cancel()
```

When signing `POST`, `PUT`, or `DELETE` requests, use request body bytes (UTF-8) as request data and the following code:

```swift
// 2FA authentication code - uses device-related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

// Sign POST call with provided data made to URI with custom identifier "/payment/create"
do {
    let header = try powerAuthSDK.authenticationHeaderForRequestWithBody(with: auth, method: "POST", uriId: "/payment/create", body: requestBodyData)
    let httpHeaderKey = header.key
    let httpHeaderValue = header.value
} catch _ {
    // In case of invalid configuration, invalid activation state, or corrupted state data
}
```

When signing `GET` or `DELETE` request with query parameters, use the following code:

```swift
// 2FA authentication code - uses device-related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

// Sign GET call with provided query parameters made to URI with custom identifier "/payment/create"
let params = [
    "param1": "value1",
    "param2": "value2"
]

do {
    let header = try powerAuthSDK.authenticationHeaderForRequestWithParams(with: auth, method: "GET", uriId: "/payment/create", params: params)
    let httpHeaderKey = header.key
    let httpHeaderValue = header.value
} catch _ {
    // In case of invalid configuration, invalid activation state, or corrupted state data
}
```

#### Request Synchronization

It is recommended that your application executes only one signed request at a time. The reason for that is that our authentication code scheme uses a counter as a representation of logical time. In other words, the order of request validation on the server is very important. If you issue more than one signed request at the same time, then the order is not guaranteed, and therefore one of the requests may fail. On top of that, Mobile SDK itself is using this type of authentication for its purposes. For example, if you ask for a token, then the SDK is using a signed request to obtain the token's data. To deal with this problem, Mobile SDK is providing a few methods that help with the signed requests synchronization.

If your networking is based on `OperationQueue`, then you can add your own `Operation` objects directly to the internal queue. Be aware that the PowerAuth authentication code must be calculated as a part of the operation's execution. For example:

```swift
let httpOperation: Operation = YourHttpOperation(...)
guard powerAuthSDK.executeOperation(onSerialQueue: httpOperation) else {
    fatalError("There's no activation")
}
```

In the case of custom networking, you can use the method to execute any block on the serial queue. In this case, the PowerAuth authentication code must be calculated as a part of the block's execution. For example:

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

### Symmetric Offline Multi-Factor Authentication Code

This type of authentication is very similar to [Symmetric Multi-Factor Authentication Code](#symmetric-multi-factor-authentication-code), but the result is provided in the form of a simple, human-readable string (unlike the online version, where the result is an HTTP header). To calculate the code, you need a typical `PowerAuthAuthentication` object to define all required factors, nonce, and data to sign. The `nonce` and `data` should also be transmitted to the application over the OOB channel (for example, by scanning a QR code). Then the authentication code calculation is straightforward:

```swift
// 2FA authentication - uses device-related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

_ = powerAuthSDK.offlineAuthenticationCode(with: auth, uriId: "/confirm/offline/operation", body: data, nonce: nonce) { authenticationCode, error in 
    if let authenticationCode {
        print("authentication code is " + authenticationCode)
    }
}
```

The application has to show that calculated code to the user now, and the user has to re-type that code into the web application for verification. 

<!-- begin box info -->
You can alter the length of the code components in the `offlineAuthenticationCodeComponentLength` property of the `PowerAuthConfiguration` object.
<!-- end -->


## Digital Signatures

Digital signatures are another form of data authentication supported in the PowerAuth protocol. The PowerAuth Mobile SDK provides a unified interface for digital signatures, allowing you to compute or verify digital signatures or MAC tokens.

### Signature Key Identifiers

To compute or verify a signature, you must specify the key used for the operation. The following basic key categories are available:

- **"master"** public keys are used to verify data signed by the server. These keys can be used with or without an activation present in the `PowerAuthSDK` instance.
- **"server"** public keys are personalized keys uniquely associated with an activation. You can use these keys to verify data signed by the server.
- **"device"** private and public keys are stored locally on the device and associated with an activation. You can use these keys to sign data and to verify previously signed data.
- **"MAC"** keys are symmetric keys used to verify MACs calculated by the server.

The table below lists all available key identifiers defined in the `PowerAuthSignatureKeyId` enumeration and operations supported with the identifier:

| Key identifier    | Key Type  | Signature       | Activation  | Sign | Verify | Description |
|-------------------|-----------|-----------------|-------------|------|--------|--------------|
| `master`          | Any       | Any or Hybrid   | No          | No   | Yes    | Use all available "master" public keys for signature verification. |
| `master_EC`       | EC        | ECDSA           | No          | No   | Yes    | Use only the EC-based "master" public key for ECDSA signature verification. |
| `master_ML_DSA`   | ML-DSA    | ML-DSA          | No          | No   | Yes    | Use only the ML-DSA-based "master" public key for ML-DSA signature verification. |
| `server`          | Any       | Any or Hybrid   | Yes         | No   | Yes    | Use all available "server" public keys for signature verification. |
| `server_EC`       | EC        | ECDSA           | Yes         | No   | Yes    | Use only the EC-based "server" public key for ECDSA signature verification. |
| `server_ML_DSA`   | ML-DSA    | ML-DSA          | Yes         | No   | Yes    | Use only the ML-DSA-based "server" public key for ML-DSA signature verification. |
| `device`          | Any       | Any or Hybrid   | Yes         | Yes  | Yes    | Use all available "device" private and public keys for signature computation or verification. |
| `device_EC`       | EC        | ECDSA           | Yes         | Yes  | Yes    | Use only the EC-based "device" private and public key for ECDSA signature computation or verification. |
| `device_ML_DSA`   | ML-DSA    | ML-DSA          | Yes         | Yes  | Yes    | Use only the ML-DSA-based "device" private and public key for ML-DSA signature computation or verification. |
| `macPersonalized` | MAC       | KMAC            | Yes         | No   | Yes    | Use the KMAC-based symmetric key for MAC verification. |

<!-- begin box info -->
If you're interested in more technical details, such as the exact algorithms used for digital signatures, see the [Digital-Signatures.md](Digital-Signatures.md) document.
<!-- end -->

#### Signature Key Availability

The availability of key types depends on the selected [PowerAuth Algorithm](#algorithms-for-communication):

- **"EC"** keys are always available.
- **"ML_DSA"** keys are available only if the `EC_P384_ML_L3` or `EC_P384_ML_L5` algorithms are used.
- **"MAC"** keys are available for all algorithms except `LEGACY_P256`.

<!-- begin box warning -->
If you select a key without specifying its exact type (for example, `.master`), it may lead to multiple key selections. For example, the `EC_P384_ML_L3` and `EC_P384_ML_L5` algorithms use two keys for each key category. The format of hybrid signatures is not yet standardized; therefore, the PowerAuth Mobile SDK supports such key identifiers only in JWS functions. JWS, by design, supports multiple keys in signatures.
<!-- end -->

### Sign Data With Device Private Key

To compute a digital signature using an asymmetric device private key, request user credentials (such as password or PIN), specify the signing key (always use the "device" key), and use the following code:

```swift
// 2FA authentication — uses the device-related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")
// Specify the key to sign with. In this case, device_ML_DSA is used,
// and therefore an ML-DSA signature will be produced.
let signingKey = PowerAuthSignatureKeyId.device_ML_DSA
// Unlock the device private key after successful authentication and perform data signing.
powerAuthSDK.calculateDigitalSignature(authentication: auth, forData: data, withKey: signingKey) { signature, error in
    if let signature {
        // Send data and signature to the server
    } else {
        // Authentication or network error
    }
}
```

<!-- begin box info -->
If the `PowerAuthSDK` instance is not configured for the legacy mode (that is, the algorithm is not `LEGACY_P256`), you can also use biometric authentication to access the device private key.
<!-- end -->


### Create JSON Web Signature with Device Private Key 

The asymmetric private key signatures described in the previous chapter can be used to create a [JSON Web Signature (JWS)](https://www.rfc-editor.org/rfc/rfc7515). The example below demonstrates how to construct a JWS from generic data:

```swift
// 2FA authentication — uses the device-related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")
// Unlock the device private key after successful authentication and perform data signing.
// - The dataType parameter is added to the JWS Protected Header under the "typ" key.
//   A nil parameter means that no "typ" value is included in the header.
// - The compact parameter determines whether the output is a JWS (compact = false) or JWT (compact = true).
powerAuthSDK.calculateJwsSignature(authentication: auth, forData: data, dataType: nil, compact: false, withKey: .device_ML_DSA) { jws, error in
    if let jws {
        // jws contains a JSON string with the JWS object
    } else {
        // Authentication or network error
    }
}
```

The following example demonstrates how to construct a signed JWT:

```swift
// Construct claims dictionary
let claims = [
    "sub": "user-id",
    "first_name": "John",
    "last_name": "Appleseed"
]
guard let claimsData = try? JSONSerialization.data(withJSONObject: claims) else {
    fatalError() // JSON serialization error
}
// 2FA authentication — uses the device-related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")
// Unlock the secure vault, fetch the private key, and perform data signing
powerAuthSDK.calculateJwsSignature(authentication: auth, forData: claimsData, dataType: "JWT", compact: true, withKey: .device_ML_DSA) { jws, error in
    if let jws {
        // jws contains the JWT string
    } else {
        // Authentication or network error
    }
}
```

### Verify Server-Signed Data

This task is useful when you receive arbitrary data from the server and need to verify that it was indeed issued by the server. The `PowerAuthSDK` provides a high-level method for validating data and its associated signature:

```swift
do {
    try powerAuthSDK.verifyDigitalSignature(signature: signature, forData: signedData, withKey: .server_ML_DSA)
    print("Signature is valid")
} catch let error as NSError where error.domain == PowerAuthErrorDomain {
    if error.powerAuthErrorCode == .wrongSignature {
        print("Signature is invalid")
    } else {
        // other cause of failure
    }
}
```

#### Verify Data Encoded in QR Code

In cases where you need to verify the authenticity of a QR code created on the server and authenticated with a personalized MAC key (for example, when authenticity is bound to an activation), use the `.macPersonalized` key identifier. For example:

```swift
do {
    try powerAuthSDK.verifyDigitalSignature(signature: signature, forData: signedData, withKey: .macPersonalized)
    print("MAC is valid")
} catch let error as NSError where error.domain == PowerAuthErrorDomain {
    if error.powerAuthErrorCode == .wrongSignature {
        print("MAC is invalid")
    } else {
        // other cause of failure
    }
}
```


### Verify JSON Web Signature

To verify a JSON Web Signature (JWS) created on the server, use the following code:

```swift
do {
    try sdk.verifyJwsSignature(signature: jws, compact: false, strict: true, withKey: .server)
} catch let error as NSError where error.domain == PowerAuthErrorDomain {
    if error.powerAuthErrorCode == .wrongSignature {
        // signature is not valid
    } else {
        // other cause of failure
    }
}
```

Explanation of `verifyJwsSignature` function parameters:

- `signature` - A string containing JWS or JWT signed data.
- `compact` - If `true`, the input string is a compact JWT; otherwise, a full JWS object is expected.
- `strict` — If `true`, all selected keys must successfully verify their corresponding signatures. If `false`, verification succeeds when at least one provided key matches a valid signature; however, invalid or mismatched signatures still result in an error. It is generally recommended to use `true`, unless you have a specific reason to reduce the strict verification.
- `key`- The identifier of the key used for verification. Be aware, that this API doesn't support `.macPersonalized` key.

<!-- begin box warning -->
The compact (JWT) format encodes only a single signature, so it is recommended to specify the exact key type (EC, ML-DSA, etc.) for verification. If a generic key identifier is provided (such as `.server`), the function may fail when the current algorithm results in multiple key selections. You can relax this behavior by setting the `strict` parameter to `false`, but this is generally not recommended. In non-strict mode, an attacker could potentially remove or replace a stronger PQC signature with a weaker one without detection.
<!-- end box -->

### Creating Certificate Signing Request

The PowerAuth SDK can create a Certificate Signing Request (CSR) that can be used to request an X.509 certificate from a Public Key Infrastructure (PKI). The CSR contains a device public key generated by the SDK and is signed with the activation-bound private key.

The created CSR is returned in PEM format, including the `-----BEGIN CERTIFICATE REQUEST-----` and `-----END CERTIFICATE REQUEST-----` lines and newline characters (`\n`).

To create a CSR, use the following code:

```swift
let authentication = PowerAuthAuthentication.possessionWithPassword(password: "1234")
let keyIdentifier = PowerAuthSignatureKeyId.device_ML_DSA

powerAuthSDK.createCertificateSigningRequest(
    authentication: authentication, // authentication object
    distinguishedNames: [ // subject's distinguished names (DN)
        "CN" : "wultra.com",
        "O"  : "Wultra",
        "C"  : "CZ"
    ],
    subjectAltNames: [ // subject's alternative names (SAN)
        "IP: 192.168.1.10",
        "email: admin@example.com"
    ],
    keyIdentifier: keyIdentifier // Key Identifier
) { csr, error in
    if let csr {
        print("CSR: \(csr)")
        // Use the CSR
    } else {
        // Handle error
    }
}
```

<!-- begin box info -->
If the `PowerAuthSDK` instance is not configured for the legacy mode (that is, the algorithm is not `LEGACY_P256`), you can also use biometric authentication to create CSR.
<!-- end -->

### Getting Device Public Keys

Use the following code to retrieve device public keys associated with the activation:

```swift
let allKeys = try powerAuthSDK.exportDevicePublicKeys(format: .der)
if let publicKey = allKeys.first(where: { $0.keyType == .EC }) {
    print("EC key algorithm: \(publicKey.keyAlgorithm)")
    print("  X.509 key data: \(publicKey.keyData.base64EncodedString())")
}
if let publicKey = allKeys.first(where: { $0.keyType == .ML_DSA }) {
    print("ML-DSA key algorithm: \(publicKey.keyAlgorithm)")
    print("      X.509 key data: \(publicKey.keyData.base64EncodedString())")
}
```

Available format specifiers:

- `.der` - The public key is exported in binary X.509 (DER) format.
- `.raw` - The raw key format depends on the key type:
  - **EC keys**: The output is ASN.1 encoded, as defined in **ANSI X9.63**.
  - **ML-DSA keys**: The output contains the raw public key obtained via OpenSSL’s `EVP_PKEY_get_raw_public_key()`.


## Password Change

The typical password-change flow in a mobile application consists of the following steps:

1. **Prompt the user for their current password.**

2. **Validate the current password with the server:**
   ```swift
   powerAuthSDK.beginPasswordChange(oldPassword: "oldPassword") { changeData, error in
       if let changeData {
           // Password is valid, keep this object aside and use in the step 4.
       } else {
           // Process error.
       }
   }
   ```
   Keep the received `changeData` object aside for later. If the user cancels the process after this step, you should either release the stored `changeData` object or call `secureClear()` to ensure that all sensitive information is destroyed:
   ```swift
   changeData.secureClear()
   ```

3. **If the current password is valid, allow the user to enter and confirm a new password.**

4. **Submit the new password to the server:**
   ```swift
   powerAuthSDK.finishPasswordChange(newPassword: "newPassword", changeData: changeData) { error in
       if let error {
           // process error
       }
   }
   ```

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

PowerAuth mobile SDK allows you to use both strings and special password objects at input, so it's up to you which way fits best for your purposes. For simplicity, this documentation uses strings for the passwords, but all code examples can be changed to utilize the `PowerAuthCorePassword` object as well. For example, this is the modified code for the first step of [Password Change](#password-change):

```swift
import PowerAuthCore

let oldPass = PowerAuthCorePassword(string: "oldPassword")
powerAuthSDK.beginPasswordChange(oldPassword: oldPass) { changeData, error in
    if let changeData {
        // Success
    } else {
        // Process error.
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

## Working with sensitive data

The PowerAuth mobile SDK is using `PowerAuthCoreData` object for manage the cryptographically sensitive data, such as encryption keys. You can encounter this object in several public API functions, such as functions for [Secure Vault](#secure-vault). This chapter explains how to use the `PowerAuthCoreData` object properly.

### Create instance of `PowerAuthCoreData`

If you need to provide cryptographically sensitive key material to PowerAuth mobile SDK, then use the following code:

```swift
let yourKey = "nbuSR123nbuSR123".data(using: .ascii)!
let secureData = PowerAuthCoreData(withData: yourKey)
```

The `secureData` object will keep copy of bytes. In case you also wants to destroy the content of source `Data` structure, then you can try an alternative constructor, that try to erase content of the source data in case the source data is instance of `NSMutableData` class:

```swift
let mutableKey = NSMutableData(data: "nbuSR123nbuSR123".data(using: .ascii)!) as Data
let secureData = PowerAuthCoreData(withDataAndClearSource: mutableKey)
```

As you can see, this unlikely happens in typical Swift projects, so you may ensure on your own that data is erased properly:

```swift
extension Data {
    mutating func secureErase() {
        resetBytes(in: 0..<count)   // Fill with zeroes
        removeAll(keepingCapacity: false) // Release memory
    }
}

var yourKey = "nbuSR123nbuSR123".data(using: .ascii)!
let secureData = PowerAuthCoreData(withData: yourKey)
yourKey.secureErase()
```

### Using instance of `PowerAuthCoreData`

To get reference to stored bytes, use the following code:

```swift
func processSecureData(secureData: PowerAuthCoreData) {
    doSomethingWitBytes(secureData.sensitiveData)
}
```

<!-- begin box warning -->
Be aware that you should not keep the reference to provided `Data` object. If you need to keep the bytes longer, then keep the reference to `SecureData` instance, or make your own copy of bytes, returned in `data` property.
<!-- end -->


## Biometry Setup

PowerAuth SDK for iOS provides an abstraction on top of the base Touch and Face ID support. While the authentication / data signing itself is nicely and transparently embedded in the `PowerAuthAuthentication` object used in [regular request signing](#data-signing), other biometry-related processes require their own API. This part of the documentation is not relevant to the **tvOS** platform.

### Check Biometry Status

You have to check for biometry on three levels:

- **System Availability**: If Touch ID or Face ID is present on the system.
- **Activation Availability**: If biometry factor data are available for given activation.
- **Application Availability**: If the user decides to use Touch ID for a given app. _(optional)_

PowerAuth SDK for iOS provides code for the first two of these checks.

#### Overall Status

To get information on whether biometric authentication is fully available, you can use the following code:

```swift
if powerAuthSDK.isAuthenticationWithBiometricsAvailable {
    // Biometric authentication is available, you can construct PowerAuthAuthentication with biometry 
} else {
    // Fallback to PIN
}
```

The function returns `true` only if activation has biometry factor-related data available and the device has a biometric sensor available and biometrics are enrolled in the system.

To get more detailed information, use the following code:

```swift
let biometricStatus = powerAuthSDK.biometricStatus
```

The next chapters explain in more detail the usage of the returned `PowerAuthBiometricStatus` object.

#### System Availability

To check whether the biometrics is available at the system level, use the following code:

```swift
// Get biometric status
let biometricStatus = powerAuthSDK.biometricStatus
switch biometricStatus.systemStatus {
    case .notSupported: print("Biometry is not supported.")
    case .notAvailable: print("Biometry is not available at this moment.")
    case .notEnrolled: print("Biometry is supported, but not enrolled.")
    case .lockout: print("Biometry is supported, but it has been locked out.")
    case .available: print("Biometry is available right now.")
}
// If you want to adjust localized strings or icons presented to the user,
// you can use the following code to determine the type of biometry available
// on the system:
switch biometricStatus.biometryType {
    case .touchID: print("You can use Touch ID")
    case .faceID: print("You can use Face ID")
    case .none: print("Biometry is not supported or not enrolled")
}
```

#### Activation Availability

To check whether activation is configured for authentication with biometrics, use the following code:

```swift
// Get biometric status
let biometricStatus = powerAuthSDK.biometricStatus
// Determine overall availability
if biometricStatus.isAuthenticationWithBiometricsAvailable {
    // Equal to call:
    //   powerAuthSDK.isAuthenticationWithBiometricsAvailable
}
// Determine whether local activation has biometric factor configured.
if biometricStatus.isBiometricFactorConfigured {
    // Equal to call
    //   powerAuthSDK.hasBiometryFactor()
}
```

#### Application Availability

The last check is fully under your control. By keeping the biometry settings flag, for example, a `bool` in `UserDefaults`, you are able to show expected user Touch or Face ID status (in a disabled state, though) even in the case biometry is not enabled or when no finger or face is enrolled on the device.


### Enable Biometry

In case an activation does not yet have biometry-related factor data, and you would like to enable Touch or Face ID support, use the following code:

```swift
// Establish biometric data using the provided password
powerAuthSDK.addBiometryFactor(password: "1234") { error in
    if let error  {
        // Error occurred, report it to the user

        // It's also recommended to fetch activation's status to synchronize biometric factor
        // configuration with the server.
    } else {
        // Everything went OK, biometry is ready to be used
    }
}
```

### Disable Biometry

To remove biometry-related factor data used by Touch or Face ID use the following code:

```swift
// Remove biometric data
powerAuthSDK.removeBiometryFactor { error in
    if let error {
        // handle error

        // It's recommended to fetch activation's status to synchronize biometric factor
        // configuration with the server.
    }
}
```

### Fetch Biometry Credentials In Advance

You can acquire biometry credentials in advance in case business processes require computing two or more different PowerAuth biometry authentication codes in one interaction with the user. To achieve this, the application must acquire the custom-created `PowerAuthAuthentication` object first and then use it for the required authentication code calculations. It's recommended to keep this instance referenced only for a limited time, required for all future authentication code calculations.

Be aware, that you must not execute the next HTTP request signed with the same credentials when the previous one fails with the 401 HTTP status code. If you do, then you risk blocking the user's activation on the server.

To obtain biometry credentials for the future authentication code calculation, call the following code:

```swift
// Authenticate user with biometry and obtain PowerAuthAuthentication credentials for future authentication code calculation.
powerAuthSDK.authenticateUsingBiometry(withPrompt: "Authenticate to sign in") { authentication, error in
    if let authentication {
        // Success, you can use the provided PowerAuthAuthentication object for the authentication code calculation.
        // The provided authentication object is preconfigured for possession+biometry factors
    }
}
```

### Biometry Factor-Related Key Lifetime

By default, the biometry factor-related key is **NOT** invalidated after the biometry enrolled in the system is changed. For example, if the user adds or removes the finger or enrolls with a new face, then the biometry factor-related key is still available for the signing operation. To change this behavior, you have to provide the `PowerAuthBiometricConfiguration` object with the `invalidateBiometricFactorAfterChange` parameter set to `true` and use that configuration for the `PowerAuthSDK` instance construction:

```swift
// Prepare your PA config
let configuration = PowerAuthConfiguration()
// ...

// Prepare PowerAuthBiometricConfiguration
// Set true to the 'invalidateBiometricFactorAfterChange' property.
let biometricConfiguration = PowerAuthBiometricConfiguration()
biometricConfiguration.invalidateBiometricFactorAfterChange = true

// Init PowerAuthSDK instance
let powerAuthSDK = try PowerAuthSDK(configuration: configuration, biometricConfiguration: biometricConfiguration, clientConfiguration: nil)
```

<!-- begin box warning -->
Be aware that the configuration above is effective only for the new keys. So, if your application is already using the biometry factor-related key with a different configuration, then the configuration change doesn't change the existing key. You have to [disable](#disable-biometry) and [enable](#enable-biometry) biometry to apply the change.
<!-- end -->

### Fallback biometry to device passcode

By default, the fallback from biometric authentication to authenticate with the device's passcode is not allowed. To change this behavior, you have to provide the `PowerAuthBiometricConfiguration` object with the `allowFallbackToDevicePasscode` parameter set to `true` and use that configuration for the `PowerAuthSDK` instance construction:

```swift
// Prepare your PA config
let configuration = PowerAuthConfiguration()
// ...

// Prepare PowerAuthBiometricConfiguration
// Set true to the 'allowFallbackToDevicePasscode' property.
let biometricConfiguration = PowerAuthBiometricConfiguration()
biometricConfiguration.allowFallbackToDevicePasscode = true

// Init PowerAuthSDK instance
let powerAuthSDK = try PowerAuthSDK(configuration: configuration, biometricConfiguration: biometricConfiguration, clientConfiguration: nil)
``` 

Once the configuration above is used, then the `invalidateBiometricFactorAfterChange` option does not affect the biometry factor-related key lifetime. 

<!-- begin box warning -->
It's not recommended to allow fallback to device passcodes if your application falls under EU banking regulations or your application needs to distinguish between the biometric and the knowledge-factor-based authentication codes. This is because if the biometry factor-related key is unlocked with the device's passcode, then it's no longer a biometric factor.
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

If you plan to pre-authorize `LAContext` and use it for multiple biometry authentication code calculations in a row, then please consider the following things first:

- Make sure that you make context invalid once it's no longer needed.
- Multiple authentication codes in a row could be problematic if your application falls under EU banking regulations.
- It would be difficult to prove that the user authorized the request if your application contains a bug and does the authentication on the user's behalf or with the wrong context.

If you still insist to re-use `LAContext` then you have to alter `PowerAuthBiometricConfiguration` and set `invalidateLocalAuthenticationContextAfterUse` to `false`.


## Biometry troubleshooting

### Biometry lockout

<!-- begin box warning -->
Note that if the biometric authentication fails with too many attempts in a row (e.g. biometry is locked out), then PowerAuth SDK will generate an invalid biometry factor-related key, and the success is reported back to the application. This is an intended behavior and as a result, it typically leads to unsuccessful authentication on the server and an increased counter of failed attempts. The purpose of this is to limit the number of attempts for attackers to deceive the biometry sensor.
<!-- end -->

### Thread-blocking operation

Be aware that if you try to calculate PowerAuth Symmetric Authentication Code with a biometric factor, then the call to the SDK function will block the calling thread while the biometric authentication dialog is displayed. So, it's not recommended to do such an operation on the main or the networking thread. For example:

```swift
let authentication = PowerAuthAuthentication.possessionWithBiometry()
let header = try? sdk.authenticationHeaderForRequestWithBody(with: authentication, method: "POST", uriId: "/some/uri-id", body: "{}".data(using: .utf8))
// The thread is blocked while the biometric dialog is displayed.
```

To avoid thread blocking, acquire the biometric key in advance:

```swift
powerAuthSDK.authenticateUsingBiometry(withPrompt: "Authenticate to sign in") { authentication, error in
    // callback is always called from the main thread
    if let authentication {
        // Success, you can use the provided PowerAuthAuthentication object for the authentication code calculation.
        // The provided authentication object is preconfigured for possession+biometry factors
    }
}
```

### Parallel biometric authentications

It's not recommended to calculate more than one authentication code with the biometric factor at the same time, or in a row at a quick pace. Both scenarios are considered an issue in the application's logic.

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

PowerAuth Standard RESTful API has a default endpoint `/pa/v3/activation/remove` for an activation removal. This endpoint uses a authentication header verification for looking up the activation to be removed. The benefit of this method is that it is already present in both PowerAuth SDK for iOS and PowerAuth Standard RESTful API - nothing has to be programmed. Also, the user does not have to be logged in to use it. However, the user has to authenticate using 2FA with either a password or biometry.

Use the following code for an activation removal using a signed request:

```swift
// 2FA authentication code - uses device-related key and user PIN code
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

Currently, PowerAuth SDK supports two basic modes of end-to-end encryption:

- In an "application" scope, the encryptor can be acquired and used during the whole lifetime of the application.
- In an "activation" scope, the encryptor can be acquired only if `PowerAuthSDK` has a valid activation. The encryptor created for this mode is cryptographically bound to the parameters agreed during the activation process. You can combine this encryption with [PowerAuth Symmetric Multi-Factor Authentication Code](#symmetric-multi-factor-authentication-code) in "encrypt-then-sign" mode.

For both scenarios, you need to acquire the `PowerAuthCoreEncryptor` object, which will then provide an interface for the request encryption and the response decryption. The object currently provides only low-level encryption and decryption methods, so you need to implement your own JSON (de)serialization and request and response processing.

The following steps are typically required for a full E2EE request and response processing:

1. Acquire the right encryptor from the `PowerAuthSDK` instance. For example:
   ```swift
   // Import PowerAuthCore to access ECIES implementation
   import PowerAuthCore
   
   // Encryptor for "application" scope.
   sdk.encryptorForApplicationScope { encryptor, error in
      if let encryptor {
        // success
      } else {
        // failure
      }
   }
   // ...or similar, for an "activation" scope.
   sdk.encryptorForActivationScope { encryptor, error in
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
   let encryptedRequest = try encryptor.encryptRequest(payloadData)
   ```

1. Extract request body and HTTP headers:
   ```swift
   let requestBody: Data = encryptedRequest.requestBody
   let requestHeaders: [PowerAuthCoreHttpHeader] = encryptedRequest.requestHeaders
   ```

1. Add all HTTP headers to the request (for signed requests, see note below):
   ```swift
    var httpRequest = URLRequest(url: URL(string: "https://example.org/encrypted-request")!)
    requestHeaders.forEach { header in
        httpRequest.addValue(header.headerValue, forHTTPHeaderField: header.headerName)
    }
   ```
   Note that if an "activation" scoped encryptor is combined with PowerAuth Symmetric Multi-Factor Authentication Code, then this step is not required. The authentication header already contains all the information required for proper request decryption on the server.

1. Fire your HTTP request and wait for a response
   - In case that non-200 HTTP status code is received, then the error processing is identical to a standard RESTful response defined in our protocol. So, you can expect a JSON object with `"error"` and `"message"` properties in the response.

1. In case of success, decrypt the response:
   ```swift
   let encryptedResponse = PowerAuthCoreEncryptedResponse(responseBody: responseBody)
   let response = try encryptor.decryptResponse(encryptedResponse)
   ```

1. And finally, you can process your received response.

As you can see, implementing end-to-end encryption is a non-trivial task. We recommend reaching out to us before deploying an application-specific E2EE solution. We can provide tailored guidance based on your specific scenario, especially once we understand your goals and use case for end-to-end encryption.


## Secure Vault

Secure Vault lets an application obtain **a base KDK** (Key Derivation Key) after a successful strong user authentication.
The base KDK is not an encryption or MAC key and cannot be used directly — instead, the application can derive purpose-specific keys from it.
This functionality is available only when the activation is already on **protocol version 4.0**.

Use Secure Vault when you need a stable, high-entropy root for deriving multiple scoped keys (encryption, MAC, wrapping keys, etc.) tied to the user’s successful strong authentication, **without persisting** those child keys. The PowerAuth Mobile SDK guarantees that the base KDKs remain stable during the lifetime of an activation.

### Key identifiers

Two base KDKs are available, depending on the authentication factors used:

- `knowledge` - available after successful authentication with possession + knowledge factors.
- `knowledgeOrBiometry` - available after any successful 2FA authentication. This key is at least as strong as `knowledge` and can be used wherever a biometry-backed flow is acceptable.

### Obtaining the "knowledge" base KDK

```swift
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")
sdk.fetchSecureVaultKey(authentication: auth, keyIdentifier: .knowledge) { vaultKey, error in
    if let vaultKey {
        do {
            // Derive a 32-byte key
            let derivedKey = try vaultKey.deriveKey(withIndex: 1000, keySize: 32)
            let keyData = derivedKey.sensitiveData
        } catch {
            // handle derivation error
        }
    } else {
        // handle acquisition error
    }
}
```

### Obtaining the "knowledgeOrBiometry" base KDK

```swift
let auth = PowerAuthAuthentication.possessionWithBiometry()
sdk.fetchSecureVaultKey(authentication: auth, keyIdentifier: .knowledgeOrBiometry) { vaultKey, error in
    if let vaultKey {
        do {
            // Derive a 32-byte key
            let derivedKey = try vaultKey.deriveKey(withIndex: 1000, keySize: 32)
            let keyData = derivedKey.sensitiveData
        } catch {
            // handle derivation error
        }
    } else {
        // handle acquisition error
    }
}
```

### Security Recommendations

- Do **not** store derived keys on the device. Always acquire the base KDK when needed and derive the keys for each specific purpose.
- **Destroy** the base KDK as soon as possible.
- Never reuse a derived key for multiple purposes (e.g., don’t use one key for both encryption and authentication).
- When encrypting different data sets, **derive a new** key with a different index.
- If your application uses multiple keys, maintain a **registry of derivation indices** to avoid accidental key reuse.

### Obtaining Legacy Encryption Key

If your activation is still using **PowerAuth protocol 3.3**, you can obtain the legacy encryption key as follows:

```swift
// 2FA authentication
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

// Select custom key index
let index = UInt64(1000)

// Fetch the encryption key with the given index
powerAuthSDK.fetchEncryptionKey(auth, index: index) { (encryptionKey, error) in
    if error == nil {
        // ... use the encryption key to encrypt or decrypt data
        let keyData = encryptionKey.sensitiveData
    } else {
        // Report error
    }
}
```

This function is useful if you still have local data encrypted with a key generated by an older SDK version. It is recommended to decrypt the data with the old key and re-encrypt it using the new key, acquired via the `fetchSecureVaultKey()` function.


## Token-Based Authentication

<!-- begin box warning -->
**WARNING:** Before you start using access tokens, please visit our [documentation for powerauth-crypto](https://github.com/wultra/powerauth-crypto/blob/develop/docs/MAC-Token-Based-Authentication.md) for more information about this feature.
<!-- end -->

The tokens are simple, locally cached objects, producing timestamp-based authentication headers. Be aware that tokens are NOT a replacement for general PowerAuth Authentication Codes. They are helpful in situations when the authentication codes are too heavy or too complicated for implementation. Each token has the following properties:

- It needs a PowerAuth authentication code for its creation (e.g., you need to provide `PowerAuthAuthentication` object)
- It has a unique identifier on the server. This identifier is not exposed to the public API, but the DEBUG version of SDK can reveal that identifier in the debugger (e.g., you can use `po tokenObject` to print the object's description)
- It has a symbolic name (e.g. "MyToken") defined by the application programmer to identify already created tokens.
- It can generate timestamp-based authentication HTTP headers.
- It can be used concurrently. Token's private data doesn't change over time.
- The token is associated with the `PowerAuthSDK` instance. So, you can use the same symbolic name in multiple SDK instances, and each created token will be unique.
- Tokens are persisted in the keychain and cached in the memory.
- Once the parent `PowerAuthSDK` instance loses its activation, all its tokens are removed from the local database.

### Getting Token

To get an access token, you can use the following code:

```swift
// 1FA authentication code - uses device-related key
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

### Generating Authentication Header

Use the following code to generate an authentication header:

```swift
let task = tokenStore.generateAuthenticationHeader(withName: "MyToken") { header, error in
    if let header = header {
        let httpHeader = [ header.key : header.value ]
        // now you can attach that httpHeader to your HTTP request
    } else {
        // failure, the token is no longer valid, or failed to synchronize time
        // with the server.
    }
}
```

Once you have a `PowerAuthToken` object, then you can use also a synchronous code to generate an authentication header:

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

## Authenticated Protocol Upgrade

The authenticated protocol upgrade procedure enables an existing activation to
migrate to a newer algorithm for communication with the PowerAuth Server.
Following conditions must be satisfied before the upgrade can proceed:

- The PowerAuth Server version must be **2.0 or later**.
- The PowerAuth SDK instance must be configured with support for at least
`EC_P384` algorithm for communication with the PowerAuth Server.

An application can check whether a protocol upgrade is available for the current
activation by invoking:

```swift
let upgradeAvailable = powerAuthSDK.hasProtocolUpgradeAvailable()
```

Note that the availability information is derived from the activation status
obtained from the PowerAuth Server. Consequently, an upgrade may become
available after a successful activation status fetch. This method is not
required to be called prior to starting the protocol upgrade.

A protocol upgrade is an authenticated operation. User must provide valid
knowledge authentication factor (e.g. password or PIN). To start the protocol
upgrade, call:

```swift
powerAuthSDK.startProtocolUpgrade(password: "1234") { (result, error) in
    if let result {
        if result.activationStatusFetchRequired {
            // Activation status fetch is required to complete the protocol upgrade
        } else {
            // Protocol upgrade is completed
        }
    } else {
        // Error occurred
    }
}
```

If the call succeeds, the application must inspect the
`activationStatusFetchRequired` field of the result object. If set to `true`,
activation status fetch must be performed to complete the protocol upgrade. Only
after successful activation status fetch is the protocol upgrade considered
completed. If the `activationStatusFetchRequired` field of the result object is
set to `false`, the protocol upgrade is considered completed without any further
action and the result object also contains new `activationFingerprint`. If an
error occurs, the PowerAuth SDK will revert to the previous activation state,
and the upgrade can be safely retried later.

Until the protocol upgrade is fully completed, the PowerAuth SDK restricts
certain functionality, such as PowerAuth authentication code calculation. To
verify whether the activation is still in the middle of an upgrade, call:

```swift
let upgradePending = powerAuthSDK.hasPendingProtocolUpgrade()
```

If this call returns true, the application must perform an activation status fetch to complete the upgrade.

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

<!-- begin box warning -->
Support for the External Encryption Key (EEK) was discontinued in PowerAuth Mobile SDK version 2.0.
<!-- end -->

In earlier SDK versions, `PowerAuthSDK` allowed you to specify an external encryption key (EEK) to provide an additional layer of protection for the knowledge and biometry factor keys. This mechanism was primarily used to create a chain of activations, where one primary `PowerAuthSDK` instance unlocked access to one or more secondary activations.

If the activation in your application is still using EEK, please use the following code at your application’s startup to remove it:

```swift
if powerAuthSDK.hasExternalEncryptionKey {
    let eek = PowerAuthCoreData(withData: eekBytes)
    try powerAuthSDK.removeExternalEncryptionKey(eek)
}
```

## Share Activation Data

This chapter explains how to share the `PowerAuthSDK` activation state between application and its extensions, or between multiple applications from the same vendor.

<!-- begin box warning -->
This feature is not supported on the macOS Catalyst platform.
<!-- end -->

<!-- begin box warning -->
If you used this feature in an SDK version older than 2.0.0, please read the [Upgrade from older SDKs](#upgrade-from-older-sdks) chapter first.
<!-- end -->

### Prepare Activation Data Sharing

The App Extension normally doesn't have access to data created by the main application, so the first step is to set up data sharing for your project.

#### Keychain Sharing

iOS SDK stores its most sensitive data into the iOS keychain, so you need to configure the keychain sharing first. If you're not familiar with keychain sharing, then don't worry about that, the keychain is shared only between the vendor's applications. So the sensitive information is not exposed to 3rd party applications.

1. Select your application project in the **Project Navigator** to navigate to the target configuration window and select the applications's target under the **TARGETS** heading in the sidebar.
2. Now select **Signing & Capabilities** tab and click **+ Capability** button.
3. Find and add **Keychain Sharing** capability.
4. Click "+" in just created **Keychain Sharing** capability and Xcode will predefine first **Keychain Group** to your application's bundle name. Let's call this value as `KEYCHAIN_GROUP_NAME`

<!-- begin box info -->
The predefined group is usually beneficial because iOS is by default using that group for storing all keychain entries created in the application. So, If your application is already using PowerAuth and you're going to just add extension support, then this is the most simple way to set up a keychain sharing.
<!-- end -->

Now you have to do a similar setup for your application's extension:

5. Select your application project in the **Project Navigator** to navigate to the target configuration window and select the extensions's target under the **TARGETS** heading in the sidebar.
6. Select **Signing & Capabilities** tab and click **+ Capability** button.
7. Find and add **Keychain Sharing** capability.
8. Click "+" in just created **Keychain Sharing** capability and add the same `KEYCHAIN_GROUP_NAME` as you did for the application's target.
9. (optional) Repeat steps 4 to 6 for all other extensions which supposed to use shared activation data.

Now you need to know your **Team ID** (the unique identifier assigned to your team by Apple). Unfortunately, the identifier is not simply visible in Xcode, so you'll have to log in to Apple's [development portal](http://developer.apple.com/account) and look for that identifier on your membership details page.

If you know the Team ID, then the final `KEYCHAIN_GROUP_IDENTIFIER` constant is composed as `TEAM_ID.KEYCHAIN_GROUP_NAME`. So, it should look like: `KTT00000MR.com.powerauth.demo.App`.

#### App Groups

The PowerAuth SDK for iOS is using one boolean flag stored in the `UserDefaults` facility, to determine whether the application has been reinstalled. Unfortunately, the `UserDefaults.standard` created by the application cannot be shared with the app extension, so you have to create a new application group to share that data.

1. Select your application project in the **Project Navigator** to navigate to the target configuration window and select the applications's target under the **TARGETS** heading in the sidebar.
2. Now select **Signing & Capabilities** tab and click **+ Capability** button.
3. Find and add **App Groups** capability.
3. Click "+" in just created **App Groups** capability add a group with the desired identifier and turn this particular group ON (e.g. make sure that the checkmark close to the group's name is selected). Let's call this value `APP_GROUP_IDENTIFIER`. If the group already exists, then just click the checkmark to turn it ON.
4. Now switch to the application's extension target, select the **Capabilities** tab, and also expand the **App Groups** section.
5. Turn "ON" **App Groups** for extension and add an app group with the same name as you did in step 3.

You can optionally check a troubleshooting section if you need to [migrate the keychain initialization flag](#userdefaults-migration) from standard user defaults to a shared one.

### Configure Activation Data Sharing

To share the activation's state just assign an instance of the `PowerAuthSharingConfiguration` object into `PowerAuthConfiguration`:

```swift
// Keychain sharing and App Group constants
let keychainSharing = "KTT00000MR.com.powerauth.demo.App"   // KEYCHAIN_GROUP_IDENTIFIER constant
let appGroup = "group.your.app.group"                       // APP_GROUP_IDENTIFIER constant
// Prepare the configuration
let configuration = PowerAuthConfiguration(
        instanceId: Bundle.main.bundleIdentifier!,
        baseEndpointUrl: "https://<your-domain>/enrollment-server",
        configuration: "ARDDj6EB6iAUtNm...KKEcBxbnH9bMk8Ju3K1wmjbA==")
// Assign sharing configuration
configuration.sharingConfiguration = PowerAuthSharingConfiguration(
    appGroup: appGroup,
    appIdentifier: "com.powerauth.demo.App", 
    keychainAccessGroup: keychainSharing)

// Create a PowerAuthSDK instance
let powerAuthSDK = try PowerAuthSDK(configuration: configuration)
```

The `PowerAuthSharingConfiguration` object contains the following properties:

- `appGroup` is the name of the app group shared between your applications. Be aware, that the length of app group encoded in UTF-8, should not exceed 26 characters. See [troubleshooting](#length-of-application-group) section for more details.
- `appIdentifier` is an identifier unique across all your applications or extensions that are supposed to use the shared activation data. You can use your applications' bundle identifiers or any other identifier that can be then identified in all your applications (such as `smartBank`, `smartBank.walletExt`, `investmentsApp`, etc.) Due to technical limitations, the length of the identifier must not exceed 127 bytes, if represented in UTF-8.
- `keychainAccessGroup` is an access group for keychain sharing.

<!-- begin box info -->
Unlike the regular configuration the `instanceId` value in `PowerAuthConfiguration` should not be derived on the application's bundle identifier. This is because all applications and extensions that share PowerAuth data must use the same identifier. To ensure consistency, use a predefined constant string or an identifier based on the first application that integrated PowerAuth. This guarantees that all related components can access the same PowerAuth instance without conflicts.
<!-- end -->

<!-- begin box warning -->
It is also strongly recommended not to use the same `appIdentifier` for more than one instance of `PowerAuthSDK` running in the same application or extension (i.e. do not share the data between multiple instances running in the same process).
<!-- end -->

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
    let header = try powerAuthSDK.authenticationHeaderForRequestWithBody(with: auth, method: "POST", uriId: "/payment/create", body: requestBodyData)
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
            print("Error code for error that occurs when activation code is invalid")
            
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

        case .wrongSignature:
            print("Digital or JWS signature is not valid.")

        case .upgradeSDK:
            print("Upgrade PowerAuth Mobile SDK in your application.")

        case .other:
            print("Unspecified error.")
            
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
- `PowerAuthErrorCode.pendingProtocolUpgrade` is reported when the requested SDK operation cannot be completed due to a pending PowerAuth protocol upgrade. You can retry the operation later. The error code is typically reported in situations when SDK is performing protocol upgrade and the application wants to calculate the PowerAuth authentication code in parallel operation. Such kind of concurrency is forbidden since SDK version `1.0.0`
- `PowerAuthErrorCode.externalPendingOperation` is reported when the requested operation collides with the same operation type already started in the external application.
- `PowerAuthErrorCode.upgradeSDK` is reported when the local activation data format is not understandable by this version of PowerAuth Mobile SDK.

### Working with Invalid SSL Certificates

Sometimes, you may need to develop or test your application against a service that runs over HTTPS protocol with an invalid (self-signed) SSL certificate. By default, the HTTP client used in PowerAuth SDK communication validates the certificate. To disable the certificate validation, add the following code just before your `PowerAuthSDK` instance configuration:

```swift
// Create a custom  `PowerAuthClientConfiguration` object:
let clientConfig = PowerAuthClientConfiguration()
clientConfig.sslValidationStrategy = PowerAuthClientSslNoValidationStrategy()
// configure the PowerAuthSDK object
let powerAuthSDK = PowerAuthSDK(
    configuration: PowerAuthConfiguration(...),
    biometricConfiguration: nil, // optional, default will be used when nil
    clientConfiguration: clientConfig
)
```

### Logs

<!-- begin box warning -->
Note that the functions below are effective only if PowerAuth SDK is compiled in the `DEBUG` build configuration or the `ENABLE_PA2_LOG` compilation flag is set.
<!-- end -->

Logs are turned off by default. To turn it on, use the following code:

```swift
PowerAuthLogSetEnabled(true)
```

To turn on an even more detailed log, use the following code:

```swift
PowerAuthLogSetVerbose(true)
```

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
        // Process the log (write to file for example)
    }
}
```

If you're handling logs with the `PowerAuthLogDelegate`, you might want to turn off the default console logs. To do so, use:

```swift
PowerAuthLogToConsoleSetEnabled(false)
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

### UserDefaults Migration

If your previous version of the application did not use shared data between the application and the extension, then you probably need to migrate the keychain status flag from `UserDefaults.standard` to a shared one. We recommend performing this migration at the main application's startup code and **BEFORE** the `PowerAuthSDK` object is configured and used:

```swift
private func migrateUserDefaults(appGroup: String) {
    guard let shared = UserDefaults(suiteName: appGroup) else {
        fatalError("AppGroup is not configured properly")
    }
    if shared.bool(forKey: PowerAuthKeychain_Initialized) {
        return // migration is not required
    }
    let standard = UserDefaults.standard
    if standard.bool(forKey: PowerAuthKeychain_Initialized) {
        standard.removeObject(forKey: PowerAuthKeychain_Initialized)
        standard.synchronize()
        shared.set(true, forKey: PowerAuthKeychain_Initialized)
        shared.synchronize()
    }
}
```

### Upgrade from older SDKs

PowerAuth Mobile SDK version `2.0.0` introduced a new internal activation data format that is incompatible with previous SDK versions. This change is particularly important if you are using the [Activation Data Sharing](#share-activation-data) feature to share activation data between multiple applications. In such a setup, you may encounter a situation where one of your applications is already upgraded to a newer SDK version and the modified data is not recognized by an application using an older SDK version. This situation may lead to unexpected removal of activation data.

To prevent this, it is very important to carefully plan how you roll out application updates to your users. It is recommended to follow these steps to reliably upgrade your applications to PowerAuth SDK 2.0 (and later):

1. First, upgrade all your applications to SDK 2.0+ and set the [algorithm](#algorithms-for-communication) to `LEGACY_P256`. In this setup, the activation data format remains fully compatible with older SDK versions.
2. Wait until a significant portion of your users are using version `2.0+` across all your applications.
3. Then switch the [algorithm](#algorithms-for-communication) to the one you intend to use going forward (for example, `EC_P384_ML_L3`).

<!-- begin box info -->
The procedure above is not required if you are using activation data sharing to share data between a single application and its extensions. This setup is safe because the extensions are part of the main application and are upgraded at the same time.
<!-- end -->

