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
    - [Activation via Custom Credentials](#activation-via-custom-credentials)
    - [Activation via Recovery Code](#activation-via-recovery-code)
    - [Customize Activation](#customize-activation)
    - [Committing Activation Data](#committing-activation-data)
    - [Validating User Inputs](#validating-user-inputs)
- [Requesting Device Activation Status](#requesting-activation-status)
- [Data Signing](#data-signing)
   - [Symmetric Multi-Factor Signature](#symmetric-multi-factor-signature)
   - [Asymmetric Private Key Signature](#asymmetric-private-key-signature)
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
- [Common SDK Tasks](#common-sdk-tasks)
- [Additional Features](#additional-features)
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

To integrate PowerAuth library into your Xcode project using CocoaPods, specify it in your `Podfile`:

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

### Manual

If you prefer not to use CocoaPods as a dependency manager, you can integrate PowerAuth into your project manually as a git [submodule](http://git-scm.com/docs/git-submodule).

#### Git Submodules

1. Open up the Terminal app and go to your top-level project directory and add the library as a submodule:
    ```sh
    $ git submodule add https://github.com/wultra/powerauth-mobile-sdk.git PowerAuthLib
    $ git submodule update --init --recursive
    ```
    The first command will clone PowerAuth SDK into `PowerAuthLib` folder, and the second will update all nested submodules.

2. Open the new `PowerAuthLib` folder, and go to `proj-xcode` sub-folder
3. Drag the `PowerAuthLib.xcodeproj` project file into **Project Navigator** of your application's Xcode project. It should appear nested underneath your application's blue project icon.
4. Select your application project in the Project Navigator to navigate to the target configuration window and select the extension's target under the **TARGETS** heading in the sidebar.
5. Now select **Build Phases** tab and expand the **Target Dependencies** section. Click on the "Plus Sign" and choose **"PowerAuth2"** framework from the **"PowerAuthLib"** project.
6. Next, in the same **Build Phases** tab, expand **Link With Libraries** section. Click on the "Plus Sign" and choose **"PowerAuth2.framework"** from the **"PowerAuthLib"** project.

### Carthage

We provide limited and experimental support for the [Carthage dependency manager](https://github.com/Carthage/Carthage). The current problem with Carthage is that we cannot specify which Xcode project and which scheme has to be used for a particular library build. It kind of works automatically, but the build process is extremely slow. So, if you still want to try to integrate our library with Carthage, try the following tips:

- Add `github "wultra/powerauth-mobile-sdk" "develop"` into your `Cartfile`. You can alternatively use any `release/X.Y.x` branch, greater or equal than `release/1.6.x`.
- It's recommended to force Carthage to use submodules for the library code checkouts.
- It's recommended to force Carthage to use XCFrameworks.
- It's recommended to update only iOS platform (if possible). So try to run something like this: `carthage update --use-xcframeworks --use-submodules --platform ios`
- If build fails on broken project `PowerAuthLib.xcodeproj` then go to `{your_project}/Carthage/Checkouts/powerauth-mobile-sdk/proj-xcode` and delete `PowerAuthLib.xcodeproj` folder. This is because git doesn't delete empty folders by default and we have removed that XCode project from the source control. 
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

- `APP_KEY` - Application key that binds activation with a specific application.
- `APP_SECRET` - Application secret that binds activation with a specific application.
- `KEY_MASTER_SERVER_PUBLIC` - Master Server Public Key, used for non-personalized encryption and server signature verification.

You also need to specify your instance ID (by default, this can be an app bundle ID). This is because one application may use more than one custom instance of `PowerAuthSDK`, and the identifier is the way to distinguish these instances while working with Keychain data.

Finally, you need to know the location of your [PowerAuth Standard RESTful API](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Standard-RESTful-API.md) endpoints. That path should contain everything that goes before the `/pa/**` prefix of the API endpoints.

To sum it up, in order to configure the `PowerAuthSDK` default instance, add the following code to your application delegate:

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

The original activation method uses a one-time activation code generated in PowerAuth Server. To create an activation using this method, some external application (Internet banking, ATM application, branch / kiosk application) must generate an activation code for you and display it (as a text or in a QR code).

Use the following code to create an activation once you have an activation code:

```swift
let deviceName = "Petr's iPhone 7" // or UIDevice.current.name
let activationCode = "VVVVV-VVVVV-VVVVV-VTFVA" // let user type or QR-scan this value

// Create activation object with given activation code.
guard let activation = try? PowerAuthActivation(activationCode: activationCode, name: deviceName) else {
    // Activation code is invalid
}

// Create a new activation with just created activation object
PowerAuthSDK.sharedInstance().createActivation(activation) { (result, error) in
    if error == nil {
        // No error occurred, proceed to credentials entry (PIN prompt, Enable Touch ID switch, ...) and commit
        // The 'result' contains 'activationFingerprint' property, representing the device public key - it may be used as visual confirmation
        // If server supports recovery codes for activations, then `activationRecovery` property contains object with information about activation recovery.
    } else {
        // Error occurred, report it to the user
    }
}
```

If the received activation result also contains recovery data, then you should display that values to the user. To do that, please read the [Getting Recovery Data](#getting-recovery-data) section of this document, which describes how to treat that sensitive information. This is relevant for all types of activation you use.

#### Additional Activation OTP

If an [additional activation OTP](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Additional-Activation-OTP.md) is required to complete the activation, then use the following code to configure the `PowerAuthActivation` object:

```swift
let deviceName = "Petr's iPhone 7" // or UIDevice.current.name
let activationCode = "VVVVV-VVVVV-VVVVV-VTFVA" // let user type or QR-scan this value
let activationOtp = "12345"

// Create activation object with given activation code.
guard let activation = try? PowerAuthActivation(activationCode: activationCode, name: deviceName)?
    .with(additionalActivationOtp: activationOtp) else {
        // Activation code is invalid
}
// The rest of the activation routine is the same.
```

<!-- begin box warning -->
Be aware that OTP can be used only if the activation is configured for ON_KEY_EXCHANGE validation on the PowerAuth server. See our [crypto documentation for details](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Additional-Activation-OTP.md#regular-activation-with-otp).
<!-- end -->

### Activation via Custom Credentials

You may also create an activation using any custom login data - it can be anything that the server can use to obtain the user ID to associate with a new activation. Since the credentials are custom, the server's implementation must be able to process such a request. Unlike the previous versions of SDK, the custom activation no longer requires a custom activation endpoint.

Use the following code to create an activation using custom credentials:

```swift
// Create a new activation with a given device name and custom login credentials
let deviceName = "Petr's iPhone 7" // or UIDevice.current.name
let credentials = [
    "username": "john.doe@example.com",
    "password": "YBzBEM"
]

// Create activation object with given credentials.
guard let activation = try? PowerAuthActivation(identityAttributes: credentials, name: deviceName) else {
    // Activation credentials are empty
}

// Create a new activation with just created activation object
PowerAuthSDK.sharedInstance().createActivation(activation) { (result, error) in
    if error == nil {
        // No error occurred, proceed to credentials entry (PIN prompt, Enable Touch ID switch, ...) and commit
        // The 'result' contains 'activationFingerprint' property, representing the device public key - it may be used as visual confirmation
        // If server supports recovery codes for activations, then `activationRecovery` property contains object with information about activation recovery.
    } else {
        // Error occurred, report it to the user
    }
}
```

Note that by using weak identity attributes to create an activation, the resulting activation is confirming a "blurry identity". This may greatly limit the legal weight and usability of a signature. We recommend using a strong identity verification before activation can actually be created.


### Activation via Recovery Code

If PowerAuth Server is configured to support [Recovery Codes](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Activation-Recovery.md), then also you can create an activation via the recovery code and PUK.

Use the following code to create an activation using recovery code:

```swift
let deviceName = "John Tramonta" // or UIDevice.current.name
let recoveryCode = "55555-55555-55555-55YMA" // User's input
let puk = "0123456789" // User's input. You should validate RC & PUK with using PowerAuthActivationCodeUtil

// Create activation object with recovery code and PUK
guard let activation = try? PowerAuthActivation(recoveryCode: recoveryCode, recoveryPuk: puk, name: deviceName) else {
    // Recovery code or PUK is not valid.
}

// Create a new activation with just created activation object
PowerAuthSDK.sharedInstance().createActivation(activation) { (result, error) in
    if let error = error {
        // Error occurred, report it to the user
        // On top of a regular error processing, you should handle a special situation, when server gives an additional information
        // about which PUK must be used for the recovery. The information is valid only when recovery code from a postcard is applied.
        if let responseError = (error.userInfo[PowerAuthErrorDomain] as? PowerAuthRestApiErrorResponse)?.responseObject {
            let currentRecoveryPukIndex = responseError.currentRecoveryPukIndex
            if currentRecoveryPukIndex > 0 {
                // The PUK index is known, you should inform user that it has to rewrite PUK from a specific position.
            }
        }
    } else {
        // No error occurred, proceed to credentials entry (PIN prompt, Enable Touch ID switch, ...) and commit
        // The 'result' contains 'activationFingerprint' property, representing the device public key - it may be used as visual confirmation
        // If server supports recovery codes for activations, then `activationRecovery` property contains object with information about activation recovery.
    }
}
```

### Customize Activation

You can set an additional properties to `PowerAuthActivation` object, before any type of activation is created. For example:

```swift
// Custom attributes that can be processed before the activation is created on PowerAuth Server.
// The dictionary may contain only values that can be serialized to JSON.
let customAttributes: [String:Any] = [
    "isNowPrimaryActivation" : true,
    "otherActivationIds" : [
        "e43f5f99-e2e9-49f2-bcae-5e32a5e96d22",
        "41dd704c-65e6-4d4b-b28f-0bc0e4eb9715"
    ]
]

// Extra flags that will be associated with the activation record on PowerAuth Server.
let extraFlags = "EXTRA_FLAGS"

// Now create the activation object with all that extra data
guard let activation = try? PowerAuthActivation(activationCode: "45AWJ-BVACS-SBWHS-ABANA", name: activationName)?
    .with(extras: extraFlags)
    .with(customAttributes: customAttributes) else {
        // Invalid activation code...
    }

// Create a new activation as usual
PowerAuthSDK.sharedInstance().createActivation(activation) { (result, error) in
    //
}
```  

### Committing Activation Data

After you create an activation using one of the methods mentioned above, you need to commit the activation - to use provided user credentials to store the activation data on the device. Use the following code to do this:

```swift
do {
    try PowerAuthSDK.sharedInstance().commitActivation(withPassword: "1234")
} catch _ {
    // happens only in case SDK was not configured or activation is not in state to be committed
}
```

This code has created activation with two factors: possession (key stored using a key derived from a device fingerprint) and knowledge (password, in our case, a simple PIN code). If you would like to enable Touch or Face ID support at this moment, use the following code instead of the one above:

```swift
do {
    let auth = PowerAuthAuthentication.commitWithPasswordAndBiometry(password: "1234")

    try PowerAuthSDK.sharedInstance().commitActivation(with: auth)
} catch _ {
    // happens only in case SDK was not configured or activation is not in state to be committed
}
```


### Validating User Inputs

The mobile SDK is providing a couple of functions in `PowerAuthActivationCodeUtil` interface, helping with user input validation. You can:

- Parse activation code when it's scanned from QR code
- Validate a whole code at once
- Validate recovery code or PUK
- Auto-correct characters typed on the fly

#### Validating Scanned QR Code

To validate an activation code scanned from QR code, you can use `PowerAuthActivationCodeUtil.parse(fromActivationCode:)` function. You have to provide the code with or without the signature part. For example:

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
if !PowerAuthSDK.sharedInstance().verifyServerSignedData(otp.activationCode.data(using: .utf8)!, signature: signature, masterKey: true) {
    // Invalid signature
}
```

#### Validating Entered Activation Code

To validate an activation code at once, you can call `PowerAuthActivationCodeUtil.validateActivationCode()` function. You have to provide the code without the signature part. For example:

```swift
let isValid   = PowerAuthActivationCodeUtil.validateActivationCode("VVVVV-VVVVV-VVVVV-VTFVA")
let isInvalid = PowerAuthActivationCodeUtil.validateActivationCode("VVVVV-VVVVV-VVVVV-VTFVA#aGVsbG8gd29ybGQ=")
```

If your application is using your own validation, then you should switch to functions provided by SDK. The reason for that is that since SDK `1.0.0`, all activation codes contain a checksum, so it's possible to detect mistyped characters before you start the activation. Check our [Activation Code](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Activation-Code.md) documentation for more details.

#### Validating Recovery Code and PUK

To validate a recovery code at once, you can call `PowerAuthActivationCodeUtil.validateRecoveryCode()` function. You can provide the whole code, which may or may not contain `"R:"` prefix. So, you can validate manually entered codes, but also codes scanned from QR. For example:

```swift
let isValid1 = PowerAuthActivationCodeUtil.validateRecoveryCode("VVVVV-VVVVV-VVVVV-VTFVA")
let isValid2 = PowerAuthActivationCodeUtil.validateRecoveryCode("R:VVVVV-VVVVV-VVVVV-VTFVA")
```

To validate PUK at once, you can call `PowerAuthActivationCodeUtil.validateRecoveryPuk()` function:

```swift
let isValid   = PowerAuthActivationCodeUtil.validateRecoveryPuk("0123456789")
```

#### Auto-Correcting Typed Characters

You can implement auto-correcting of typed characters with using `PowerAuthActivationCodeUtil.validateAndCorrectTypedCharacter()` function in screens, where user is supposed to enter an activation or recovery code. This technique is possible due to the fact that Base32 is constructed so that it doesn't contain visually confusing characters. For example, `1` (number one) and `I` (capital I) are confusing, so only `I` is allowed. The benefit is that the provided function can correct typed `1` and translate it to `I`.

Here's an example how to iterate over the string and validate it character by character:

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

To obtain a detailed activation status information, use the following code:

```swift
// Check if there is some activation on the device
if PowerAuthSDK.sharedInstance().hasValidActivation() {

    // If there is an activation on the device, check the status with the server
    PowerAuthSDK.sharedInstance().fetchActivationStatus() { (status, error) in

        // If no error occurred, process the status
        if let status = status {
            // Activation state: .created, .pendingCommit, .blocked, .removed, .deadlock
            switch status.state {
            case .pendingCommit:
                // Activation is awaiting commit on the server.
                print("Waiting for commit")
            case .active:
                // Activation is valid and active.
                print("Activation is active")
            case .blocked:
                // Activation is blocked. You can display unblock
                // instructions to the user.
                print("Activation is blocked")
            case .removed:
                // Activation is no longer valid on the server.
                // You can inform user about this situation and remove
                // activation locally.
                print("Activation is no longer valid")
                PowerAuthSDK.sharedInstance().removeActivationLocal()
            case .deadlock:
                // Local activation is technically blocked and no longer
                // can be used for the signature calculations. You can inform
                // user about this situation and remove activation locally.
                print("Activation is technically blocked")
                PowerAuthSDK.sharedInstance().removeActivationLocal()
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

            if let customObject = customObject {
                // Custom object contains any proprietary server specific data
            }

        } else {
            // Network error occurred, report it to the user
        }
    }

} else {
    // No activation present on device
}
```

Note that the status fetch may fail at an unrecoverable error `PowerAuthErrorCode.protocolUpgrade`, meaning that it's not possible to upgrade the PowerAuth protocol to a newer version. In this case, it's recommended to [remove the activation locally](#activation-removal).

To get more information about activation states, check the [Activation States](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Activation.md#activation-states) chapter available in our [powerauth-crypto](https://github.com/wultra/powerauth-crypto) repository.

## Data Signing

The main feature of the PowerAuth protocol is data signing. PowerAuth has three types of signatures:

- **Symmetric Multi-Factor Signature**: Suitable for most operations, such as login, new payment, or confirming changes in settings.
- **Asymmetric Private Key Signature**: Suitable for documents where a strong one-sided signature is desired.
- **Symmetric Offline Multi-Factor Signature**: Suitable for very secure operations, where the signature is validated over the out-of-band channel.
- **Verify server signed data**: Suitable for receiving arbitrary data from the server.

### Symmetric Multi-Factor Signature

To sign request data, you need to first obtain user credentials (password, PIN code, Touch ID scan) from the user. The task of obtaining the user credentials is used in more use-cases covered by the SDK. The core class is `PowerAuthAuthentication` that holds information about the used authentication factors:

```swift
// 1FA signature, uses device related key only.
let oneFactor = PowerAuthAuthentication.possession()

// 2FA signature, uses device related key and user PIN code.
let twoFactorPassword = PowerAuthAuthentication.possessionWithPassword(password: "1234")

// 2FA signature, uses biometry factor-related key as a 2nd. factor.
let twoFactorBiometry = PowerAuthAuthentication.possessionWithBiometry()

// Alternative biometry authentications with prompt
let twoFactorBiometryPrompt = PowerAuthAuthentication.possessionWithBiometry(prompt: "Please authenticate with biometry to log-in.")
```

When signing `POST`, `PUT` or `DELETE` requests, use request body bytes (UTF-8) as request data and the following code:

```swift
// 2FA signature, uses device related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

// Sign POST call with provided data made to URI with custom identifier "/payment/create"
do {
    let signature = try PowerAuthSDK.sharedInstance().requestSignature(with: auth, method: "POST", uriId: "/payment/create", body: requestBodyData)
    let httpHeaderKey = signature.key
    let httpHeaderValue = signature.value
} catch _ {
    // In case of invalid configuration, invalid activation state or corrupted state data
}
```

When signing `GET` requests, use the same code as above with normalized request data as described in specification, or (preferably) use the following helper method:

```swift
// 2FA signature, uses device related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

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
    // In case of invalid configuration, invalid activation state or corrupted state data
}
```

#### Request Synchronization

It is recommended that your application executes only one signed request at the time. The reason for that is that our signature scheme is using a counter as a representation of logical time. In other words, the order of request validation on the server is very important. If you issue more that one signed request at the same time, then the order is not guaranteed and therefore one from the requests may fail. On top of that, Mobile SDK itself is using this type of signatures for its own purposes. For example, if you ask for token, then the SDK is using signed request to obtain the token's data. To deal with this problem, Mobile SDK is providing a few methods which helps with the signed requests synchronization.

If your networking is based on `OperationQueue`, then you can add your own `Operation` objects directly to the internal queue. Be aware that PowerAuth signature, must be calculated as a part of operation's execution. For example:

```swift
let httpOperation: Operation = YourHttpOperation(...)
guard PowerAuthSDK.sharedInstance().executeOperation(onSerialQueue: httpOperation) else {
    fatalError("There's no activation")
}
```

In case of custom networking, you can use method to execute any block on the serial queue. In this case, PowerAuth signature must be calculated as a part of block's execution. For example:

```swift
PowerAuthSDK.sharedInstance().executeBlock(onSerialQueue: { internalTask in
    yourNetworking.post(yourRequest, completionHandler: { (data, response, error) in
        // Your response processing...
        // No matter what happens, you have to call task.cancel() at the end
        internalTask.cancel()
    }, cancelationHandler: {
        // In case that your networking cancels the request, the given task
        // must be also canceled
        internalTask.cancel()
    })
})
```

### Asymmetric Private Key Signature

Asymmetric Private Key Signature uses a private key stored in the PowerAuth secure vault. In order to unlock the secure vault and retrieve the private key, the user has to first authenticate using the symmetric multi-factor signature with at least two factors. This mechanism protects the private key on the device - the server plays a role of a "doorkeeper" and holds the vault unlock key.

This process is completely transparent on the SDK level. To compute an asymmetric private key signature, request user credentials (password, PIN) and use the following code:

```swift
// 2FA signature, uses device related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

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

This type of signature is very similar to [Symmetric Multi-Factor Signature](#symmetric-multi-factor-signature), but the result is provided in the form of a simple, human-readable string (unlike the online version, where the result is HTTP header). To calculate the signature, you need a typical `PowerAuthAuthentication` object to define all required factors, nonce, and data to sign. The `nonce` and `data` should also be transmitted to the application over the OOB channel (for example, by scanning a QR code). Then the signature calculation is straightforward:

```swift
// 2FA signature, uses device related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

do {
    let signature = try PowerAuthSDK.sharedInstance().offlineSignature(with: auth, uriId: "/confirm/offline/operation", body: data, nonce: nonce)
    print("Signature is " + signature)
} catch _ {
    // In case of invalid configuration, invalid activation state or other error
}
```

The application has to show that calculated signature to the user now, and the user has to re-type that code into the web application for verification.

### Verify Server-Signed Data

This task is useful whenever you need to receive arbitrary data from the server and you need to be able to verify that the server has issued the data. The PowerAuthSDK provides a high-level method for validating data and associated signature:  

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

Since the device does not know the password and is unable to verify the password without the help of the server-side, you need to first call an endpoint that verifies a signature computed with the password. SDK offers two ways to do that.

The safe but typically slower way is to use the following code:

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

This method calls `/pa/v3/signature/validate` under the hood with a 2FA signature with provided original password to verify the password correctness.

However, using this method does not usually fit the typical UI workflow of a password change. The method may be used in cases where an old password and a new password are on a single screen, and therefore are both available at the same time. In most mobile apps, however, the user first visits a screen to enter an old password, and then (if the password is OK), the user proceeds to the two-screen flow of a new password setup (select password, confirm password). In other words, the workflow works like this:

1. Show a screen to enter an old password.
2. Check the old password on the server.
3. If the old password is OK, then let the user chose and confirm a new one.
4. Change the password by re-encrypting the activation data.

For this purpose, you can use the following code:

```swift
// Ask for an old password
let oldPassword = "1234"

// Validate password on the server
PowerAuthSDK.sharedInstance().validatePassword(password: oldPassword) { (error) in
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

<!-- begin box warning -->
**Now, beware!** Since the device does not know the actual old password, you need to make sure that the old password is validated before you use it in `unsafeChangePassword`. In case you provide the wrong old password, it will be used to decrypt the original data, and these data will be encrypted using a new password. As a result, the activation data will be broken and irreversibly lost.
<!-- end -->


## Working with passwords securely

PowerAuth mobile SDK uses `PowerAuthCorePassword` object behind the scene, to store user's password or PIN securely. The object automatically wipes out the plaintext password on its destroy, so there are no traces of sensitive data left in the memory. You can easily enhance your application's runtime security by adopting this object in your code and this chapter explains in detail how to do it.

### Problem explanation

If you store the user's password in simple string, there is a high probabilty that the content of the string will remain in the memory until the same region is reused by the underlying memory allocator. This is due the fact that the general memory allocator doesn't cleanup the region of memory being freed. It just update its linked-list of free memory regions for future reuse, so the content of allocated object typically remains intact. This has the following implications to your application:

- If your application is using system keyboard to enter the password or PIN, then the sensitive data will remain in memory in multiple copies for a while. 

- If the device's memory is not stressed enough, then the application may remain in memory active for days.

The situation that the user's password stays in memory for days may be critical in situations when the attacker has the device in possession. For example, if device is lost or is in repair shop. To minimize the risks, the `PowerAuthCorePassword` object does the following things:

- Always keeps user's password scrambled with a random data, so it cannot be easily found by simple string search. The password in plaintext is revealed only for a short and well defined time when it's needed for the cryptographic operation.

- Always clears buffer with the sensitive data before the object's deinitialization.

- Doesn't provide a simple interface to reveal the password in plaintext<sup>1)</sup> and therefore it minimizes the risks of revealing the password by accident (like print it to the log).

<!-- begin box info -->
**Note 1:** There's `validatePasswordComplexity()` function that reveal the password in plaintext for the limited time for the complexity validation purposes. The straightforward naming of the function allows you to find all its usages in your code and properly validate all codepaths.
<!-- end -->

### Special password object usage

PowerAuth mobile SDK allows you to use both strings and special password objects at input, so it's up to you which way fits best for your purposes. For simplicity, this documentation is using strings for the passwords, but all code examples can be changed to utilize `PowerAuthCorePassword` object as well. For example, this is the modified code for [Password Change](#password-change):

```swift
import PowerAuthCore

// Change password from "oldPassword" to "newPassword".
let oldPass = PowerAuthCorePassword(string: "oldPassword")
let newPass = PowerAuthCorePassword(string: "newPassword")
PowerAuthSDK.sharedInstance().changePassword(from: oldPass, to: newPass) { (error) in
    if error == nil {
        // Password was changed
    } else {
        // Error occurred
    }
}
```

### Entering PIN

If your application is using system numberic keyboard to enter user's PIN then you can migrate to `PowerAuthCorePassword` object right now. We recommend you to do the following things:

- Implement your own PIN keyboard UI

- Make sure that password object is allocated and referenced only in the PIN keyboard controller and is deallocated when user leaves the controller.

- Use `PowerAuthCoreMutablePassword` that allows you to manipulate with the content of the PIN 

Here's the simple pseudo-controller example:

```swift
class EnterPinScene {
    let desiredPinLength = 4
    var pin: PowerAuthCoreMutablePassword!
    
    func onEnterScene() {
        // Allocate pin when entering to the scene
        pin = PowerAuthCoreMutablePassword()
    }
    
    func onLeaveScene() {
        // Dereference the password object, when user is leaving
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

Unfortunately, there's no simple solution for this scenario. It's quite difficult to re-implement the whole keyboard on your own, so we recommend you to keep using the system keyboard. You can still create the `PowerAuthCorePassword` object from already entered string:

```swift
let passwordString = "nbusr123"
let password = PowerAuthCorePassword(string: passwordString)
```

### Create password from data

In case that passphrase is somehow created externally in form of array of bytes, then you can instantiate it from the `Data` object directly:

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

// This is an actual complexity validator that also accepts pointer at its input. You should avoid
// converting provided memory into Data or String due to fact, that it will lead to an uncontrolled
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

PowerAuth SDK for iOS provides an abstraction on top of the base Touch and Face ID support. While the authentication / data signing itself is nicely and transparently embedded in the `PowerAuthAuthentication` object used in [regular request signing](#data-signing), other biometry-related processes require their own API. This part of the documentation is not relevant for the **tvOS** platform.

### Check Biometry Status

You have to check for biometry on three levels:

- **System Availability**:
  - If Touch ID is present on the system and if an iOS version is 9+
  - If Face ID is present on the system and if an iOS version is 11+
- **Activation Availability**: If biometry factor data are available for given activation.
- **Application Availability**: If user decided to use Touch ID for given app. _(optional)_

PowerAuth SDK for iOS provides code for the first two of these checks.

To check if you can use biometry on the system, use the following code from the `PowerAuthKeychain` class:

```swift
// Is biometry available and is enrolled on the system?
let canUseBiometry = PowerAuthKeychain.canUseBiometricAuthentication

// Or alternative, to get supported biometry type
let supportedBiometry = PowerAuthKeychain.supportedBiometricAuthentication
switch supportedBiometry {
    case .touchID: print("You can use Touch ID")
    case .faceID: print("You can use Face ID")
    case .none: print("Biometry is not supported or not enrolled")
}

// Or more complex, with full information about type and current status
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
let hasBiometryFactor = PowerAuthSDK.sharedInstance().hasBiometryFactor()
```

The last check is fully under your control. By keeping the biometry settings flag, for example, a `BOOL` in `NSUserDefaults`, you are able to show expected user Touch or Face ID status (in a disabled state, though) even in the case biometry is not enabled or when no finger or face is enrolled on the device.

### Enable Biometry

In case an activation does not yet have biometry-related factor data, and you would like to enable Touch or Face ID support, the device must first retrieve the original private key from the secure vault for the purpose of key derivation. As a result, you have to use a successful 2FA with a password to enable biometry support.

Use the following code to enable biometric authentication:

```swift
// Establish biometric data using provided password
PowerAuthSDK.sharedInstance().addBiometryFactor(password: "1234") { (error) in
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

### Fetch Biometry Credentials In Advance

You can acquire biometry credentials in advance in case that business processes require computing two or more different PowerAuth biometry signatures in one interaction with the user. To achieve this, the application must acquire the custom-created `PowerAuthAuthentication` object first and then use it for the required signature calculations. It's recommended to keep this instance referenced only for a limited time, required for all future signature calculations.

Be aware, that you must not execute the next HTTP request signed with the same credentials when the previous one fails with the 401 HTTP status code. If you do, then you risk blocking the user's activation on the server.

In order to obtain biometry credentials for the future signature calculation, call the following code:

```swift
// Authenticate user with biometry and obtain PowerAuthAuthentication credentials for future signature calculation.
PowerAuthSDK.sharedInstance().authenticateUsingBiometry(withPrompt: "Authenticate to sign in") { authentication, error in
    if let authentication = authentication {
        // Success, you can use provided PowerAuthAuthentication object for the signature calculation.
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

By default, the biometry factor-related key is **NOT** invalidated after the biometry enrolled in the system is changed. For example, if the user adds or removes the finger or enrolls with a new face, then the biometry factor-related key is still available for the signing operation. To change this behavior, you have to provide `PowerAuthKeychainConfiguration` object with `linkBiometricItemsToCurrentSet` parameter set to `true` and use that configuration for the `PowerAuthSDK` instance construction:

```swift
// Prepare your PA config
let configuration = PowerAuthConfiguration()
// ...

// Prepare PowerAuthKeychainConfiguration
// Set true to 'linkBiometricItemsToCurrentSet' property.
let keychainConfiguration = PowerAuthKeychainConfiguration()
keychainConfiguration.linkBiometricItemsToCurrentSet = true

// Init shared PowerAuthSDK instance
PowerAuthSDK.initSharedInstance(configuration, keychainConfiguration: keychainConfiguration, clientConfiguration: nil)
// ...or create your own
let sdk = PowerAuthSDK(configuration: configuration, keychainConfiguration: keychainConfiguration, clientConfiguration: nil)
```

<!-- begin box warning -->
Be aware that the configuration above is effective only for the new keys. So, if your application is already using the biometry factor-related key with a different configuration, then the configuration change doesn't change the existing key. You have to [disable](#disable-biometry) and [enable](#enable-biometry) biometry to apply the change.
<!-- end -->

### Fallback biometry to device passcode

By default, the fallback from biometric authentication to authenticate with device's passcode is not allowed. To change this behavior, you have to provide `PowerAuthKeychainConfiguration` object with `allowBiometricAuthenticationFallbackToDevicePasscode` parameter set to `true` and use that configuration for the `PowerAuthSDK` instance construction:

```swift
// Prepare your PA config
let configuration = PowerAuthConfiguration()
// ...

// Prepare PowerAuthKeychainConfiguration
// Set true to 'allowBiometricAuthenticationFallbackToDevicePasscode' property.
let keychainConfiguration = PowerAuthKeychainConfiguration()
keychainConfiguration.allowBiometricAuthenticationFallbackToDevicePasscode = true

// Init shared PowerAuthSDK instance
PowerAuthSDK.initSharedInstance(configuration, keychainConfiguration: keychainConfiguration, clientConfiguration: nil)
// ...or create your own
let sdk = PowerAuthSDK(configuration: configuration, keychainConfiguration: keychainConfiguration, clientConfiguration: nil)
``` 

Once the configuration above is used, then `linkBiometricItemsToCurrentSet` option has no effect on the biometry factor-related key lifetime. 

<!-- begin box warning -->
It's not recommended to allow fallback to device passcode if your application falls under EU banking regulations or your application needs to distinguish between the biometric and the knowledge-factor based signatures. This is due to the fact that if the biometry factor-related key is unlocked with the device's passcode, then it's no longer a biometric signature.
<!-- end -->

### LAContext support

In case you require advanced customization to system biometric dialog, then you can use your own `LAContext` instance set to `PowerAuthAuthentication` or in some functions. For example:

```swift
// Prepare LAContext
let laContext = LAContext()
laContext.localizedReason = "Authenticate to remove activation"

// Prepare PowerAuthAuthentication with context
let authentication = PowerAuthAuthentication.possessionWithBiometry(context: laContext)
// Now you can use authentication in some functions...
PowerAuthSDK.sharedInstance().removeActivation(with: authentication) { error in
    // ...
}

// Fetch biometry key in advance, with using LAContext
PowerAuthSDK.sharedInstance().authenticateUsingBiometry(withContext: laContext) { authentication, error in
    if let authentication = authentication {
        // success
    }
}
```

The usage of `LAContext` has the following limitations:

- It's effective from iOS 11 because on the older operating systems the context doesn't support essential properties, such as `localizedReason`.
- Don't alter `interactionNotAllowed` property. If you do, then the internal SDK implementation rejects the context and error is reported.

Be aware that PowerAuth automatically invalidates the application provided `LAContext` after use. This is because once the context is successfully evaluated then it can be used for a quite long time to fetch the data protected with the biometry with no prompt displayed. The exact time of validity is undocumented, but our experiments show that iOS prompts for biometric authentication again after more than 5 minutes.

If you plan to pre-authorize `LAContext` and use it for multiple biometry signature calculations in a row, then please consider the following things first:

- Make sure that you make context invalid once it's no longer needed.
- Multiple signatures in a row could be problematic if your application falls under EU banking regulations.
- It would be difficult to prove that the user authorized the request if your application contains a bug and do the signature on the user's behalf or with the wrong context.

If you still insist to re-use `LAContext` then you have to alter `PowerAuthKeychainConfiguration` and set `invalidateLocalAuthenticationContextAfterUse` to `false`.


## Biometry troubleshooting

### Biometry lockout

<!-- begin box warning -->
Note that if the biometric authentication fails with too many attempts in a row (e.g. biometry is locked out), then PowerAuth SDK will generate an invalid biometry factor related key and the success is reported back to the application. This is an intended behavior and as the result, it typically lead to unsuccessful authentication on the server and increased counter of failed attempts. The purpose of this is to limit the number of attempts for attacker to deceive the biometry sensor.
<!-- end -->

### Thread blocking operation

Be aware that if you try to calculate PowerAuth Symmetric Signature with a biometric factor, then the call to the SDK function will block the calling thread while the biometric authentication dialog is displayed. So, it's not recommended to do such an operation on the main thread. For example:

```swift
let authentication = PowerAuthAuthentication.possessionWithBiometry()
let header = try? sdk.requestSignature(with: authentication, method: "POST", uriId: "/some/uri-id", body: "{}".data(using: .utf8))
// The thread is blocked while the biometric dialog is displayed.
```

### Parallel biometric authentications

It's not recommended to calculate more than one signature with the biometric factor at the same time, or in a row at a quick pace. Both scenarios are considered an issue in the application's logic.

To prevent the first case, PowerAuth mobile SDK is using a global mutex that guarantees that only one attempt to get the biometry-protected data at the time is performed. If your application issue another signing operation while the system dialog is displayed, then this attempt ends with `.biometryCancel` error.

There's another similar issue on devices supporting FaceID. The FaceID technology behaves slightly differently than TouchID and if you try to use biometry too soon after previous successful authentication, then the 2nd attempt will fail with an authentication error. This is undocumented, but we believe it's related to the animation presented to the user after successful authentication. You simply cannot request another biometric authentication while the animation is still playing.
 

### Use pre-authorized LAContext

If you want more control over biometric authentication UI flow, then you can prepare `LAContext` and evaluate it on your own. The pre-authorized context can be then used to construct `PowerAuthAuthentication`:

```swift
let context = LAContext()
context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Please authenticate with biometry") { success, error in
    guard success && error == nil else {
        // Biometric error handling
        return
    }
    let authentication = PowerAuthAuthentication.possessionWithBiometry(context: context)
    // Now you can use authentication object in any SDK function that accept authentication with biometric factor.
}
```

Be aware that the example above doesn't handle all quirks related to the PowerAuth protocol, so you should prefer to use `authenticateUsingBiometry()` function instead:

```swift
let context = LAContext()
context.localizedReason = "Please authenticate with biometry"
PowerAuthSDK.sharedInstance().authenticateUsingBiometry(withContext: context) { authentication, error in
    guard let authentication = authentication else {
        if let nsError = error as? NSError {
            if nsError.domain == PowerAuthErrorDomain {
                if nsError.powerAuthErrorCode == .biometryCancel {
                    // cancel, app cancel, system cancel...
                } else if nsError.powerAuthErrorCode == .biometryFallback {
                    // fallback button pressed
                }
                // If you're interested in exact failure reason, then extract
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

You can clear activation data anytime from the Keychain. The benefit of this method is that it does not require help from the server, and the user does not have to be logged in. The issue with this removal method is simple: The activation still remains active on the server-side. This, however, does not have to be an issue in your case.

To remove only data related to PowerAuth SDK for iOS, use the `PowerAuthKeychain` class:

```swift
PowerAuthSDK.sharedInstance().removeActivationLocal()
```

### Removal via Authenticated Session

Suppose your server uses an authenticated session for keeping the users logged in. In that case, you can combine the previous method with calling your proprietary endpoint to remove activation for the currently logged-in user. The advantage of this method is that activation does not remain active on the server. The issue is that the user has to be logged in (the session must be active and must have activation ID stored) and that you have to publish your own method to handle this use case.

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

PowerAuth Standard RESTful API has a default endpoint `/pa/v3/activation/remove` for an activation removal. This endpoint uses a signature verification for looking up the activation to be removed. The benefit of this method is that it is already present in both PowerAuth SDK for iOS and PowerAuth Standard RESTful API - nothing has to be programmed. Also, the user does not have to be logged in to use it. However, the user has to authenticate using 2FA with either password or biometry.

Use the following code for an activation removal using signed request:

```swift
// 2FA signature, uses device related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

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

Currently, PowerAuth SDK supports two basic modes of end-to-end encryption, based on the ECIES scheme:

- In an "application" scope, the encryptor can be acquired and used during the whole lifetime of the application.
- In an "activation" scope, the encryptor can be acquired only if `PowerAuthSDK` has a valid activation. The encryptor created for this mode is cryptographically bound to the parameters agreed during the activation process. You can combine this encryption with [PowerAuth Symmetric Multi-Factor Signature](#symmetric-multi-factor-signature) in "sign-then-encrypt" mode.

For both scenarios, you need to acquire the `PowerAuthCoreEciesEncryptor` object, which will then provide interface for the request encryption and the response decryption. The object currently provides only low-level encryption and decryption methods, so you need to implement your own JSON (de)serialization and request and response processing.

The following steps are typically required for a full E2EE request and response processing:

1. Acquire the right encryptor from the `PowerAuthSDK` instance. For example:
   ```swift
   // Import PowerAuthCore to access ECIES implementation
   import PowerAuthCore
   
   // Encryptor for "application" scope.
   guard let encryptor = powerAuthSDK.eciesEncryptorForApplicationScope() else { ...failure... }
   // ...or similar, for an "activation" scope.
   guard let encryptor = powerAuthSDK.eciesEncryptorForActivationScope() else { ...failure... }
   ```

2. Serialize your request payload, if needed, into a sequence of bytes. This step typically means that you need to serialize your model object into a JSON formatted sequence of bytes.

3. Encrypt your payload:
   ```swift
   guard let cryptogram = encryptor.encryptRequest(payloadData) else { ...failure... }
   ```

4. Construct a JSON from provided cryptogram object. The dictionary with the following keys is expected:
   - `ephemeralPublicKey` property fill with `cryptogram.keyBase64`
   - `encryptedData` property fill with `cryptogram.bodyBase64`
   - `mac` property fill with `cryptogram.macBase64`
   - `nonce` property fill with `cryptogram.nonceBase64`

   So, the final request JSON should look like this:
   ```json
   {
      "ephemeralPublicKey" : "BASE64-DATA-BLOB",
      "encryptedData": "BASE64-DATA-BLOB",
      "mac" : "BASE64-DATA-BLOB",
      "nonce" : "BASE64-NONCE"
   }
   ```

5. Add the following HTTP header (for signed requests, see note below):
   ```swift
   // Acquire a "metadata" object, which contains additional information for the request construction
   guard let metadata = encryptor.associatedMetaData else { ...should never happen... }
   let httpHeaderName = metadata.httpHeaderKey
   let httpHeaderValue = metadata.httpHeaderValue
   ```
   Note that if an "activation" scoped encryptor is combined with PowerAuth Symmetric Multi-Factor signature, then this step is not required. The signature's header already contains all information required for proper request decryption on the server.

6. Fire your HTTP request and wait for a response
   - In case that non-200 HTTP status code is received, then the error processing is identical to a standard RESTful response defined in our protocol. So, you can expect a JSON object with `"error"` and `"message"` properties in the response.

7. Decrypt the response. The received JSON typically looks like this:
   ```json
   {
      "encryptedData": "BASE64-DATA-BLOB",
      "mac" : "BASE64-DATA-BLOB"
   }
   ```
   So, you need to create yet another "cryptogram" object, but with only two properties set:
   ```swift
   let responseCryptogram = PowerAuthCoreEciesCryptogram()
   responseCryptogram.bodyBase64 = response.getEncryptedData()
   responseCryptogram.macBase64 = response.getMac()

   guard let responseData = encryptor.decryptResponse(responseCryptogram) else { ... failed to decrypt data ... }
   ```

8. And finally, you can process your received response.

As you can see, the E2EE is quite a non-trivial task. We recommend contacting us before using an application-specific E2EE. We can provide you more support on a per-scenario basis, especially if we first understand what you try to achieve with end-to-end encryption in your application.

## Secure Vault

PowerAuth SDK for iOS has basic support for an encrypted secure vault. At this moment, the only supported method allows your application to establish an encryption / decryption key with a given index. The index represents a "key number" - your identifier for a given key. Different business logic purposes should have encryption keys with a different index value.

On a server-side, all secure vault-related work is concentrated in a `/pa/v3/vault/unlock` endpoint of PowerAuth Standard RESTful API. In order to receive data from this response, the call must be authenticated with at least 2FA (using password or PIN).

<!-- begin box warning -->
Secure vault mechanism does not support biometry by default. Use PIN code or password based authentication for unlocking the secure vault, or ask your server developers to enable biometry for vault unlock call by configuring PowerAuth Server instance.
<!-- end -->

### Obtaining Encryption Key

In order to obtain an encryption key with a given index, use the following code:

```swift
// 2FA signature. It uses device-related key and user PIN code.
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

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

## Recovery Codes

The recovery codes allow your users to recover their activation in case that mobile device is lost or stolen. Before you start, please read the [Activation Recovery](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Activation-Recovery.md) document, available in our [powerauth-crypto](https://github.com/wultra/powerauth-crypto) repository.

To recover an activation, the user has to re-type two separate values:

1. Recovery Code itself, which is very similar to an activation code. So you can detect typing errors before you submit such code to the server.
1. PUK, which is an additional numeric value and acts as a one-time password in the scheme.

PowerAuth currently supports two basic types of recovery codes:

1. Recovery Code bound to a previous PowerAuth activation.
   - This type of code can be obtained only in an already activated application.
   - This type of code has only one PUK available, so only one recovery operation is possible.
   - The activation associated with the code is removed once the recovery operation succeeds.

2. Recovery Code delivered via OOB channel, typically in the form of a securely printed postcard, delivered by the post service.
   - This type of code has typically more than one PUK associated with the code, so it can be used multiple times.
   - The user has to keep that postcard in safe and secure place, and mark already used PUKs.
   - The code delivery must be confirmed by the user before the code can be used for a recovery operation.

The feature is not automatically available. It must be enabled and configured on PowerAuth Server. If it's so, then your mobile application can use several methods related to this feature.

### Getting Recovery Data

If the recovery data was received during the activation process, then you can later display that information to the user. To check existence of recovery data and get that information, use the following code:

```swift
let powerAuthSdk = PowerAuthSDK.sharedInstance()
guard powerAuthSdk.hasActivationRecoveryData() else {
    // Recovery information is not available
    return
}

// 2FA signature, uses device related key and user PIN code
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
- You should require PIN code every time to display the values on the screen.
- You should warn user that taking screenshot of the values is not recommended.
- Do not cache the values in RAM.

You should inform the user that:

- Making a screenshot when values are displayed on the screen is dangerous.
- The user should write down that values on paper and keep it as much safe as possible for future use.


### Confirm Recovery Postcard

The recovery postcard can contain the recovery code and multiple PUK values on one printed card. Due to security reasons, this kind of recovery code cannot be used for the recovery operation before the user confirms its physical delivery. To confirm such recovery code, use the following code:

```swift
// 2FA signature with possession factor is required
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

let recoveryCode = "VVVVV-VVVVV-VVVVV-VTFVA" // You can also use code scanned from QR
PowerAuthSDK.sharedInstance().confirmRecoveryCode(recoveryCode, authentication: auth) { alreadyConfirmed, error in
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

- It needs PowerAuth signature for its creation (e.g., you need to provide `PowerAuthAuthentication` object)
- It has a unique identifier on the server. This identifier is not exposed to the public API, but DEBUG version of SDK can reveal that identifier in the debugger (e.g., you can use `po tokenObject` to print object's description)
- It has a symbolic name (e.g. "MyToken") defined by the application programmer to identify already created tokens.
- It can generate timestamp-based authorization HTTP headers.
- It can be used concurrently. Token's private data doesn't change in time.
- The token is associated with the `PowerAuthSDK` instance. So, you can use the same symbolic name in multiple SDK instances, and each created token will be unique.
- Tokens are persisted in the keychain and cached in the memory.
- Once the parent `PowerAuthSDK` instance loses its activation, all its tokens are removed from the local database.

### Getting Token

To get an access token, you can use the following code:

```swift
// 1FA signature, uses device related key
let auth = PowerAuthAuthentication.possession()

let tokenStore = PowerAuthSDK.sharedInstance().tokenStore

let task = tokenStore.requestAccessToken(withName: "MyToken", authentication: auth) { (token, error) in
    if let token = token {
        // now you can generate header
    } else {
        // handle error
    }
}
```

The request is performed synchronously or asynchronously depending on whether the token is locally cached on the device. You can test this situation by calling `tokenStore.hasLocalToken(withName: "MyToken")`. If operation is asynchronous, then `requestAccessToken()` returns cancellable task.

### Generating Authorization Header

Once you have a `PowerAuthToken` object, use the following code to generate an authorization header:

```swift
if let header = token.generateHeader() {
    let httpHeader = [ header.key : header.value ]
    // now you can attach that httpHeader to your HTTP request
} else {
    // in case of nil, token is no longer valid
}
```

### Removing Token From the Server

To remove the token from the server, you can use the following code:

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

### Removing Token Locally

To remove token locally, you can simply use the following code:

```swift
let tokenStore = PowerAuthSDK.sharedInstance().tokenStore
// Remove just one token
tokenStore.removeLocalToken(withName: "MyToken")
// Remove all local tokens
tokenStore.removeAllLocalTokens()
```

Note that by removing tokens locally, you will lose control of the tokens stored on the server.


## Apple Watch Support

This part of the documentation describes how to add support for Apple Watch into your PowerAuth powered iOS application. This part of the documentation is not relevant for the **tvOS** platform.

### Prepare Watch Connectivity

The PowerAuth SDK for iOS is using the [WatchConnectivity framework](https://developer.apple.com/documentation/watchconnectivity) to achieve data synchronization between iPhone and Apple Watch devices. If you're not familiar with this framework, take a look at least at [WCSession](https://developer.apple.com/documentation/watchconnectivity/wcsession) and [WCSessionDelegate](https://developer.apple.com/documentation/watchconnectivity/wcsessiondelegate) interfaces before you start.

The PowerAuth SDK doesn't manage the state of the `WCSession` and it doesn't set the delegate to the session's singleton instance. It's up to you to properly configure and activate the default session, but the application has to cooperate with PowerAuth SDK to process the messages received from the counterpart device. To do this, PowerAuth SDKs on both sides are providing `PowerAuthWCSessionManager` class which can help you process all incoming messages. Here's an example, how you can implement simple `SessionManager` for IOS:

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
        if PowerAuthWCSessionManager.sharedInstance.processReceivedMessageData(messageData, replyHandler: nil) {
            return // processed...
        }
        // Other SDKs, or your own messages can be handler here...
        print("SessionManager.didReceiveMessageData did not process message.")
    }

    func session(_ session: WCSession, didReceiveMessageData messageData: Data, replyHandler: @escaping (Data) -> Void) {
        // Try to process PowerAuth messages...
        if PowerAuthWCSessionManager.sharedInstance.processReceivedMessageData(messageData, replyHandler: replyHandler) {
            return // processed...
        }
        // Other SDKs, or your own messages can be handler here...
        print("SessionManager.didReceiveMessageData did not process message. Responding with empty data")
        replyHandler(Data())
    }

    func session(_ session: WCSession, didReceiveUserInfo userInfo: [String : Any] = [:]) {
        // Try to process PowerAuth messages...
        if PowerAuthWCSessionManager.sharedInstance.processReceivedUserInfo(userInfo) {
            return // processed...
        }
        // Other SDKs, or your own messages can be handler here...
        print("SessionManager.didReceiveUserInfo did not process message.")
    }
}
```

<!-- begin box info -->
The code above is very similar to its [watchOS counterpart](./PowerAuth-SDK-for-watchOS.md#prepare-watch-connectivity).
<!-- end -->

The example is implementing only a minimum set of methods from `WCSessionDelegate` protocol to make message passing work. The important part is that at some point, both applications (iOS and watchOS) have to call `SessionManager.shared.activateSession()` to make the transfers possible. Once you activate your session on the device, you can use all APIs related to the communication.


### WCSession Activation Sequence

In this chapter, we will discuss the right initialization sequence for various interoperating objects during your application's startup. We recommend to follow those rules to make communication between iOS & watchOS reliable.

#### Implementation Summary

On the application's startup:

1. Instantiate and configure all `PowerAuthSDK` instances and especially ones to be synchronized with Apple Watch.
2. Activate `WCSession`, so get the default instance, assign your delegate and call `activate()`
3. Wait for the session's activation in your delegate
4. Now you can use watch-related methods from PowerAuth SDK for iOS. For example, you can use a lazy method to send the status of activation to the watch device.

#### Implementation Details

Due to our internal implementation details, each `PowerAuthSDK` instance is registered to `PowerAuthWCSessionManager` for incoming message processing. The registration is done in the object's designated init method, and the de-registration is automatic after the SDK object is destroyed. This technique works great but depends on the existence of the right object at the right time.

Once you activate `WCSession`, your `WCSessionDelegate` is going to receive messages (on the background thread) from the counterpart watch application. We are highlighting the importance of the right activation sequence because your watchOS application can wake up its iOS counterpart. Therefore, it is highly possible that some messages will be available right at the application's startup. If you don't follow the guidelines and forget to prepare your `PowerAuthSDK` instances before the `WCSession` is activated, then a couple of messages may be lost.

Fortunately, the situation on watchOS side is much easier because all incoming messages are processed in one special service class, which is always available.


### Sending Activation Status to Watch

Before you start using PowerAuth on watchOS, it is recommended to send information about PowerAuth activation from iPhone to Apple Watch. The information transmitted to the watch is very limited. In fact, on the watchOS side, you can check only whether the activation on iPhone is locally present or not. It is recommended to keep this status up to date as much as possible. That typically means that you may send status every time you complete or remove the activation.

To send current status of the activation, use the following code:

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

<!-- begin box warning -->
Sending status of `PowerAuthSDK` instance that is currently without activation also effectively removes all associated tokens from Apple Watch.
<!-- end -->

### Sending Token to Watch

Once you have a `PowerAuthToken` object, use the following code to send it to the Apple Watch:

```swift
if let token = tokenStore.localToken(withName: "MyToken") {
    if !token.sendToWatch() {
        // send message has not been issued, WCSession is probably not available / active
    } else {
        // message has been issued and it's guaranteed that it will be delivered to watch
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

You can remotely remove token from a paired Apple Watch:

```swift
if let token = tokenStore.localToken(withName: "MyToken") {
    if !token.removeFromWatch() {
        // send message has not been issued, WCSession is probably not available / active
    } else {
        // message has been issued and it's guaranteed that it will be delivered to watch
    }
}
```

There is also an asynchronous version, but paired watch has to be reachable at the time of the call:

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

1. Assign EEK into `externalEncryptionKey` property of `PowerAuthConfiguration` in the time of `PowerAuthSDK` object creation.
   - This is the most convenient way of using EEK, but the key must be known at the time of `PowerAuthSDK` instantiation.
   - Once the `PowerAuthSDK` instance creates a new activation, then the factor keys will be automatically protected with EEK.
   
2. Use `PowerAuthSDK.setExternalEncryptionKey()` to set EEK after the `PowerAuthSDK` instance is created.
   - This is useful in case EEK is not known during the `PowerAuthSDK` instance creation.
   - You can set the key in any `PowerAuthSDK` state, but be aware that the method will fail in case the instance has a valid activation that doesn't use EEK.
   - It's safe to set the same EEK multiple times.

3. Use `PowerAuthSDK.addExternalEncryptionKey()` to add EEK and protect the factor keys in case that `PowerAuthSDK` has already a valid activation.
   - This method is useful in case `PowerAuthSDK` already has a valid activation, but it doesn't use EEK yet.
   - The method automatically adds EEK into the internal configuration structure, but be aware, that all future `PowerAuthSDK` usages (e.g. after app restart) require to set EEK by configuration, or by the `setExternalEncryptionKey()` method.

You can remove EEK from an existing activation if the key is no longer required. To do this, use `PowerAuthSDK.removeExternalEncryptionKey()` method. Be aware, that EEK must be set by configuration, or by the `setExternalEncryptionKey()` method before you call the remove method. You can also use the `PowerAuthSDK.hasExternalEncryptionKey` property to test whether the key is already set and in use.


## Share Activation Data

This chapter explains how to share `PowerAuthSDK` activation state between multiple applications from the same vendor. Before you start, you should read [Prepare Data Sharing](PowerAuth-SDK-for-iOS-Extensions.md#prepare-data-sharing) chapter from PowerAuth SDK for iOS Extensions to configure *Keychain Sharing* and *App Groups* in your Xcode project. 

<!-- begin box warning -->
This feature is not supported on macOS Catalyst platform.
<!-- end -->

### Configure Activation Data Sharing

To share activation's state just assign an instance of `PowerAuthSharingConfiguration` object into `PowerAuthConfiguration`:

```swift
// Prepare the configuration
let configuration = PowerAuthConfiguration()
// Standard configuration
configuration.instanceId = "SharedInstance"
configuration.appKey = "sbG8gd...MTIzNA=="
configuration.appSecret = "aGVsbG...MTIzNA=="
configuration.masterServerPublicKey = "MTIzNDU2Nz...jc4OTAxMg=="
configuration.baseEndpointUrl = "https://localhost:8080/demo-server"
// Assign sharing configuration
configuration.sharingConfiguration = PowerAuthSharingConfiguration(
    appGroup: "group.your.app.group", 
    appIdentifier: "com.powerauth.demo.App", 
    keychainAccessGroup: "KTT00000MR.com.powerauth.demo.App")

// Configure default PowerAuthSDK instance
PowerAuthSDK.initSharedInstance(configuration)
```

The `PowerAuthSharingConfiguration` object contains the following properties:

- `appGroup` is a name of app group shared between your applications.
- `appIdentifier` is an identifier unique across your all applications that suppose to use the shared activation data. You can use your applications' bundle identifiers or any other identifier that can be then processed in all your applications. Due to technical limitations, the length of identifier must not exceed 127 bytes, if represented in UTF-8.
- `keychainAccessGroup` is an access group for keychain sharing.

Unlike the regular configuration the `instanceId` value in `PowerAuthConfiguration` should not be based on application's bundle identifier. This is due the fact that all your applications must use the same identifier, so it's recommended to use some predefined constant string.


### External pending operations

Some operations, such as activation process, must be exclusively finished in application that initiated the operation. For example, if you start an activation process in one app, then all other applications that use the same shared activation data may receive a failure with `PowerAuthErrorCode.externalPendingOperation` error code until the operation is finished. To prevent such errors you can determine this state in advance:

```swift
if let externalOperation = PowerAuthSDK.sharedInstance().externalPendingOperation {
    print("Application \(externalOperation.externalApplicationId) already started \(externalOperation.externalOperationType)")
}
```

The same `PowerAuthExternalPendingOperation` object can be also extracted from the `NSError` error. For example:

```swift
PowerAuthSDK.sharedInstance().createActivation(activation) { (result, error) in
    if let error = error {
        if let externalOperation = error.powerAuthExternalPendingOperation {
            print("Application \(externalOperation.externalApplicationId) already started \(externalOperation.externalOperationType)")
        }
    }
}
``` 


## Common SDK Tasks

### Error Handling

Most of the SDK methods return an error object of an `NSError` class in case something goes wrong. Of course, it is your responsibility to handle errors these objects represent. There are two ways how you can obtain an error object from PowerAuth SDK for iOS.

In most cases, you receive an error object via a callback, like in this example:

```swift
PowerAuthSDK.sharedInstance().fetchActivationStatus { (status, error) in
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

<!-- begin box info -->
The original Objective-C code uses a method with the `BOOL` return type that passes `NSError**` (pointer to error object) as a method parameter. This syntax is automatically converted to exceptions when using code in Swift.
<!-- end -->

Errors that are caused by PowerAuth SDK for iOS use `PowerAuthErrorDomain` and `PowerAuthErrorCode` enumeration available via `NSError.powerAuthErrorCode` property. Use these values to determine the type of error. In principle, all errors should be handled in a very similar manner. Use this code snippet for inspiration:

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
            
        default:
            print("Unknown error")
        }
    }
}
```

Note that you typically don't need to handle all error codes reported in the `Error` object, or report all that situations to the user. Most of the codes are informational and help the developers properly integrate SDK into the application. A good example is `PowerAuthErrorCode.invalidActivationState`, which typically means that your application's logic is broken and you're using PowerAuthSDK in an unexpected way.

Here's the list of important error codes, which the application should properly handle:

- `PowerAuthErrorCode.biometryCancel` is reported when the user cancels the biometric authentication dialog
- `PowerAuthErrorCode.biometryFallback` is reported when the user cancels the biometric authentication dialog with a fallback button
- `PowerAuthErrorCode.protocolUpgrade` is reported when SDK failed to upgrade itself to a newer protocol version. The code may be reported from `PowerAuthSDK.fetchActivationStatus()`. This is an unrecoverable error resulting in the broken activation on the device, so the best situation is to inform the user about the situation and remove the activation locally.
- `PowerAuthErrorCode.pendingProtocolUpgrade` is reported when the requested SDK operation cannot be completed due to a pending PowerAuth protocol upgrade. You can retry the operation later. The code is typically reported in the situations when SDK is performing protocol upgrade on the background (as a part of activation status fetch), and the application want's to calculate PowerAuth signature in parallel operation. Such kind of concurrency is forbidden since SDK version `1.0.0`
- `PowerAuthErrorCode.externalPendingOperation` is reported when the requested operation collide with the same operation type already started in the external application.

### Working with Invalid SSL Certificates

Sometimes, you may need to develop or test your application against a service that runs over HTTPS protocol with an invalid (self-signed) SSL certificate. By default, the HTTP client used in PowerAuth SDK communication validates the certificate. To disable the certificate validation, add the following code just before your `PowerAuthSDK` instance configuration:

```swift
// Set `PowerAuthClientSslNoValidationStrategy as the default client SSL certificate validation strategy`
PowerAuthClientConfiguration.sharedInstance().sslValidationStrategy = PowerAuthClientSslNoValidationStrategy()
```

<!-- begin box info -->
Note that since SDK version `0.18.0`, changing `PowerAuthClientConfiguration` no longer affects networking for previously instantiated `PowerAuthSDK` objects.
<!-- end -->

### Debugging

The debug log is by default turned off. To turn it on, use the following code:

```swift
PowerAuthLogSetEnabled(true)
```

To turn-on even more detailed log, use the following code:

```swift
PowerAuthLogSetVerbose(true)
```

<!-- begin box warning -->
Note that the functions above are effective only if PowerAuth SDK is compiled in `DEBUG` build configuration.
<!-- end -->

## Additional Features

PowerAuth SDK for iOS contains multiple additional features that are useful for mobile apps.

### Password Strength Indicator

Choosing a weak passphrase in applications with high-security demands can be potentially dangerous. You can use our [Wultra Passphrase Meter](https://github.com/wultra/passphrase-meter) library to estimate the strength of the passphrase and warn the user when he tries to use such a passphrase in your application.

### Debug Build Detection

It is sometimes useful to switch PowerAuth SDK to a DEBUG build configuration to get more logs from the library:

- **CocoaPods:** a majority of the SDK is distributed as source codes, so it will match your application's build configuration. Only a low-level C++ codes and several wrapper classes on top of those are precompiled into a static library.
- **Manual installation:** Xcode is matching build configuration across all nested projects, so you usually don't need to care about the configuration switching.

The DEBUG build is usually helpful during the application development, but on the other hand, it's highly unwanted in production applications. For this purpose, the `PowerAuthSystem.isInDebug()` method provides information whether the PowerAuth library was compiled in DEBUG configuration. It is a good practice to check this flag and crash the process when the production application is linked against the DEBUG PowerAuth:

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

- `PowerAuthBasicHttpAuthenticationRequestInterceptor` to add basic HTTP authentication header to all requests
- `PowerAuthCustomHeaderRequestInterceptor` to add a custom HTTP header to all requests

For example:

```swift
let basicAuth = PowerAuthBasicHttpAuthenticationRequestInterceptor(username: "gateway-user", password: "gateway-password")
let customHeader = PowerAuthCustomHeaderRequestInterceptor(headerKey: "X-CustomHeader", value: "123456")
let clientConfig = PowerAuthClientConfiguration()
clientConfig.requestInterceptors = [ basicAuth, customHeader ]
```

We don't recommend implementing the `PowerAuthHttpRequestInterceptor` protocol on your own. The interface allows you to tweak the requests created in the `PowerAuthSDK` but also gives you an opportunity to break things. So, rather than create your own interceptor, contact us and describe what use-case is missing. Also, keep in mind that the interface may change in the future. We can guarantee the API stability of public classes implementing this interface, but not the stability of the interface itself.

### Custom User-Agent

The `PowerAuthClientConfiguration` contains `userAgent` property that allows you to set a custom value for "User-Agent" HTTP request header for all requests initiated by the library:

```swift
let clientConfig = PowerAuthClientConfiguration()
clientConfig.userAgent = "MyClient/1.0.0"
```

The default value of the property is composed as "APP-EXECUTABLE/APP-VERSION PowerAuth2/PA-VERSION (OS/OS-VERSION, DEVICE-INFO)", for example: "MyApp/1.0 PowerAuth2/1.7.0 (iOS 15.2, iPhone12.1)". The information about application executable and version is get from main bundle and its `Info.plist`.

If you set `nil` to the `userAgent` property, then the default "User-Agent" provided by the operating system will be used. 


## Troubleshooting

### tvOS support in CocoaPods

The tvOS SDK is not required by default since the SDK version 1.7.7. If your build or development machine doesn't have tvOS SDK installed, then the `PowerAuthCore` module is precompiled with no tvOS platform included in the final xcframework. Due to fact that CocoaPods keep various build artefacts in its cache, then this might be problematic in case you'll add support for tvOS later, during the development. To fix such possible issues, please remove `PowerAuthCore` pod from the cache:

```sh
pod cache clean 'PowerAuthCore' --all
```
