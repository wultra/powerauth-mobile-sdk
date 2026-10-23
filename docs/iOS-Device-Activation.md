# Device Activation

<!-- SIDEBAR _Sidebar_iOS.md -->

After you configure the SDK instance, you are ready to make your first activation.

## Activation via Activation Code

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

### Additional Activation OTP

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

## Activation via OpenID Connect

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

## Activation via Custom Credentials

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

## Customize Activation

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

## Persisting Activation Data

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


## Validating User Inputs

The mobile SDK provides a couple of functions in the `PowerAuthActivationCodeUtil` interface, helping with user input validation. You can:

- Parse activation code when it's scanned from QR code
- Validate a whole code at once
- Auto-correct characters typed on the fly

### Validating Scanned QR Code

To validate an activation code scanned from the QR code, you can use the `PowerAuthActivationCodeUtil.parse(fromActivationCode:)` function. You have to provide the code with or without the signature part. For example:

```swift
let scannedCode = "VVVVV-VVVVV-VVVVV-VTFVA#MEYCIQD4cqcWloM9PFcdgKemMH4fvXvZhYtm0HU2VI/pCFII8AIhAKGAC3YKjtS0aH99A71JBv27BR7p7gJf+EFsmsGlX5qm"
guard let parsed = PowerAuthActivationCodeUtil.parse(fromActivationCode: scannedCode) else {
    // Invalid code
    return
}
// Extract activation code
let activationCode = parsed.activationCode
```

The previous versions of PowerAuth Mobile SDK (older than 2.0) allowed you to verify the signature part extracted from a scanned QR code. This is no longer possible due to the fact that PQC signatures are too big to be embedded in a QR code. If the activation code with a signature is used in the activation process, then the signature part is ignored. You can still use `PowerAuthActivationCodeUtil` class to parse the scanned code and strip the signature part from it as the example above shows.

### Validating Entered Activation Code

To validate an activation code at once, you can call the `PowerAuthActivationCodeUtil.validateActivationCode()` function. You have to provide the code without the signature part. For example:

```swift
let isValid   = PowerAuthActivationCodeUtil.validateActivationCode("VVVVV-VVVVV-VVVVV-VTFVA")
let isInvalid = PowerAuthActivationCodeUtil.validateActivationCode("VVVVV-VVVVV-VVVVV-VTFVA#aGVsbG8gd29ybGQ=")
```

If your application is using your own validation, then you should switch to functions provided by SDK. The reason for that is that since SDK `1.0.0`, all activation codes contain a checksum, so it's possible to detect mistyped characters before you start the activation. Check our [Activation Code](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Activation-Code.md) documentation for more details.

### Auto-Correcting Typed Characters

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

## Read Next

- [Requesting Device Activation Status](iOS-Requesting-Device-Activation-Status.md)
