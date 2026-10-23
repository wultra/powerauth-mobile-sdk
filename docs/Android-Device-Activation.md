# Device Activation

<!-- SIDEBAR _Sidebar_Android.md -->

After you configure the SDK instance, you are ready to make your first activation.

## Activation via Activation Code

The original activation method uses a one-time activation code generated in PowerAuth Server. To create an activation using this method, some external application (Internet banking, ATM application, branch / kiosk application) must generate an activation code for you and display it (as a text or in a QR code).

In case you would like to use QR code scanning to enter an activation code, you can use any library of your choice, for example [Barcode Scanner](https://github.com/dm77/barcodescanner) open-source library based on ZBar lib.

Use the following code to create an activation once you have an activation code:

```kotlin
val deviceName = "Petr's Leagoo T5C"
val activationCode = "VVVVV-VVVVV-VVVVV-VTFVA" // let user type or QR-scan this value

// Create activation object with given activation code.
val activation: PowerAuthActivation
try {
    activation = PowerAuthActivation.Builder.activation(activationCode, deviceName).build()
} catch (e: PowerAuthErrorException) {
    // Invalid activation code
}

// Create a new activation with the given activation object
powerAuthSDK.createActivation(activation, object: ICreateActivationListener {
    override fun onActivationCreateSucceed(result: CreateActivationResult) {
        val fingerprint = result.activationFingerprint
        // No error occurred, proceed to credentials entry (PIN prompt, Enable "Fingerprint Authentication" switch, ...) and persist
        // The 'fingerprint' value represents the combination of device and server public keys - it may be used as visual confirmation
    }

    override fun onActivationCreateFailed(t: Throwable) {
        // Error occurred, report it to the user
    }
})
```

### Additional Activation OTP

If an [additional activation OTP](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Advanced-Activation-Flows.md#additional-user-authentication-using-activation-otp) is required to complete the activation, then use the following code to configure the `PowerAuthActivation` object:

```kotlin
val deviceName = "Petr's iPhone 7" // or UIDevice.current.name
val activationCode = "VVVVV-VVVVV-VVVVV-VTFVA" // let user type or QR-scan this value
val activationOtp = "12345"

// Create an activation object with the given activation code and OTP.
val activation: PowerAuthActivation
try {
    activation = PowerAuthActivation.Builder.activation(activationCode, deviceName)
        .setAdditionalActivationOtp(activationOtp)
        .build();
} catch (e: PowerAuthErrorException) {
    // Invalid activation code
}
// The rest of the activation routine is the same.
```

<!-- begin box warning -->
Be aware that OTP can be used only if the activation is configured for ON_KEY_EXCHANGE validation on the PowerAuth server. See our [crypto documentation for details](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Advanced-Activation-Flows.md#regular-activation-with-otp).
<!-- end -->

## Activation via OpenID Connect

You may also create an activation using OIDC protocol:

```kotlin
// Create a new activation with a given device name and login credentials
val deviceName = "Juraj's JiaYu S3"
// Get the following information from your OpenID provider
val providerId = "1234567890abcdef"
val code = "1234567890abcdef"
val nonce = "K1mP3rT9bQ8lV6zN7sW2xY4dJ5oU0fA1gH29o"
val codeVerifier = "G3hsI1KZX1o~K0p-5lT3F7yZ4...6yP8rE2wO9n" // code verifier is optional

// Create an activation object with the given credentials.
val activation: PowerAuthActivation
try {
    activation = PowerAuthActivation.Builder.oidcActivation(providerId, code, nonce, codeVerifier)
                    .setActivationName(deviceName)
                    .build()
} catch (e: PowerAuthErrorException) {
    // Credentials dictionary is empty
}

// Create a new activation with the given activation object
powerAuthSDK.createActivation(activation, object: ICreateActivationListener {
    override fun onActivationCreateSucceed(result: CreateActivationResult) {
        val fingerprint = result.activationFingerprint
        // No error occurred, proceed to credentials entry (PIN prompt, Enable "Biometric Authentication" switch, ...) and persist
        // The 'fingerprint' value represents the combination of device and server public keys - it may be used as visual confirmation
    }

    override fun onActivationCreateFailed(t: Throwable) {
        // Error occurred, report it to the user
    }
})
```

## Activation via Custom Credentials

You may also create an activation using any custom login data - it can be anything that the server can use to obtain the user ID to associate with a new activation. Since the credentials are custom, the server's implementation must be able to process such a request. Unlike the previous versions of SDK, the custom activation no longer requires a custom activation endpoint.

Use the following code to create an activation using custom credentials:

```kotlin
// Create a new activation with a given device name and login credentials
val deviceName = "Juraj's JiaYu S3"
val credentials = mapOf("username" to "john.doe@example.com", "password" to "YBzBEM")

// Create an activation object with the given credentials.
val activation: PowerAuthActivation
try {
    activation = PowerAuthActivation.Builder.customActivation(credentials, deviceName).build()
} catch (e: PowerAuthErrorException) {
    // Credentials dictionary is empty
}

// Create a new activation with the given activation object
powerAuthSDK.createActivation(activation, object: ICreateActivationListener {
    override fun onActivationCreateSucceed(result: CreateActivationResult) {
        val fingerprint = result.activationFingerprint
        // No error occurred, proceed to credentials entry (PIN prompt, Enable "Biometric Authentication" switch, ...) and persist
        // The 'fingerprint' value represents the combination of device and server public keys - it may be used as visual confirmation
    }

    override fun onActivationCreateFailed(t: Throwable) {
        // Error occurred, report it to the user
    }
})
```

Note that by using weak identity attributes to create an activation, the resulting activation confirms a "blurry identity". This may greatly limit the legal weight and usability of a signature. We recommend using a strong identity verification before activation can actually be created.

## Customize Activation

You can set additional properties to `PowerAuthActivation` object before any type of activation is created. For example:

```kotlin
val deviceName = "Petr's Leagoo T5C"
val activationCode = "VVVVV-VVVVV-VVVVV-VTFVA" // let user type or QR-scan this value

// Custom attributes that can be processed before the activation is created on PowerAuth Server.
// The dictionary may contain only values that can be serialized to JSON.
val otherIds = arrayOf(
    "e43f5f99-e2e9-49f2-bcae-5e32a5e96d22",
    "41dd704c-65e6-4d4b-b28f-0bc0e4eb9715"
)
val customAttributes = mapOf<String, Any>(
    "isPrimaryActivation" to true,
    "otherActivationIds" to otherIds
)

// Extra flags that will be associated with the activation record on PowerAuth Server.
val extraFlags = "EXTRA_FLAGS"

// Now create the activation object with all that extra data
val activation: PowerAuthActivation
try {
    activation = PowerAuthActivation.Builder.activation(activationCode, deviceName)
        .setCustomAttributes(customAttributes)
        .setExtras(extraFlags)
        .build();
} catch (e: PowerAuthErrorException) {
    // Invalid activation code
}
// The rest of the activation routine is the same.
```

## Persisting Activation Data

After you create an activation using one of the methods mentioned above, you need to persist the activation - to use provided user credentials to store the activation data on the device. Use the following code to do this.

```kotlin
// Persist activation using given PIN
val authentication = PowerAuthAuthentication.persistWithPassword(pin)
val cancelable = powerAuthSDK.persistActivationWithAuthentication(context, authentication, object: IPersistActivationListener {
    override fun onPersistActivationSucceeded() {
        // Success
    }

    override fun onPersistActivationFailed(error: Throwable) {
        // Failure
    }

    override fun onPersistActivationCancelled(userCancel: Boolean) {
        if (userCancel) {
            // user cancelled the biometric authentication dialog
        } else {
            // Your application canceled the provided cancelable object
        }
    }
})
```

This code has created activation with two factors: possession (key stored using a key derived from a device fingerprint) and knowledge (password, in our case, a simple PIN code). If you would like to enable biometric authentication support at this moment, use the following code instead of the one above:

```kotlin
// Prepare biometric prompt.
val biometricPrompt = PowerAuthBiometricPrompt.Builder(parentFragment)  // You can also use fragment activity in the constructor
                        .setTitle("Enable Biometric Authentication")
                        .setDescription("To enable biometric authentication, use the biometric sensor on your device.")
                        .build()
// Persist activation using given PIN and biometry
val authentication = PowerAuthAuthentication.persistWithPasswordAndBiometry(pin, biometricPrompt)
val cancelable = powerAuthSDK.persistActivationWithAuthentication(context, authentication, object: IPersistActivationListener {
    override fun onPersistActivationSucceeded() {
        // Success
    }

    override fun onPersistActivationFailed(error: Throwable) {
        // Failure
    }

    override fun onPersistActivationCancelled(userCancel: Boolean) {
        if (userCancel) {
            // user cancelled the biometric authentication dialog
        } else {
            // Your application canceled the provided cancelable object
        }
    }
})
```

If `PowerAuthSDK` is configured to do not authenticate on biometric key setup (e.g. `PowerAuthBiometricConfiguration` has `authenticateOnBiometricKeySetup` set to `false`), then you can use a "dummy" biometric prompt to simplify your code:

```kotlin
// Prepare biometric prompt.
val biometricPrompt = PowerAuthBiometricPrompt.noPromptForBiometricKeySetup(parentFragment)
// Persist activation using given PIN and biometry
val authentication = PowerAuthAuthentication.persistWithPasswordAndBiometry(pin, biometricPrompt)
val cancelable = powerAuthSDK.persistActivationWithAuthentication(context, authentication, object: IPersistActivationListener {
    // Example is the same as above
})
```

## Validating User Inputs

The mobile SDK provides a couple of functions in `ActivationCodeUtil` class, helping with user input validation. You can:

- Parse activation code when it's scanned from QR code
- Validate a whole code at once
- Auto-correct characters typed on the fly

### Validating Scanned QR Code

To validate an activation code scanned from QR code, you can use `ActivationCodeUtil.parseFromActivationCode()` function. You have to provide the code with or without the signature part. For example:

```kotlin
val scannedCode = "VVVVV-VVVVV-VVVVV-VTFVA#MEYCIQD4cqcWloM9PFcdgKemMH4fvXvZhYtm0HU2VI/pCFII8AIhAKGAC3YKjtS0aH99A71JBv27BR7p7gJf+EFsmsGlX5qm"
val parsed = ActivationCodeUtil.parseFromActivationCode(scannedCode);
if (parsed == null || parsed?.activationCode == null) {
    // Invalid code
    return;
}
// Extract activation code
val activationCode = parsed.activationCode
```

The previous versions of PowerAuth Mobile SDK (older than 2.0) allowed you to verify the signature part extracted from a scanned QR code. This is no longer possible due to the fact that PQC signatures are too big to be embedded in a QR code. If the activation code with a signature is used in the activation process, then the signature part is ignored. You can still use `ActivationCodeUtil` class to parse the scanned code and strip the signature part from it as the example above shows.


### Validating Entered Activation Code

To validate an activation code at once, you can call `ActivationCodeUtil.validateActivationCode()` function. You have to provide the code without the signature part. For example:

```kotlin
val isValid = ActivationCodeUtil.validateActivationCode("VVVVV-VVVVV-VVVVV-VTFVA")
val isInvalid = ActivationCodeUtil.validateActivationCode("VVVVV-VVVVV-VVVVV-VTFVA#aGVsbG8gd29ybGQ=")
```

If your application is using your own validation, then you should switch to functions provided by SDK. The reason for that is that since SDK `1.0.0`, all activation codes contain a checksum, so it's possible to detect mistyped characters before you start the activation. Check our [Activation Code](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Activation-Code.md) documentation for more details.

### Auto-Correcting Typed Characters

You can implement auto-correcting of typed characters by using `ActivationCodeUtil.validateAndCorrectTypedCharacter()` function in screens, where the user is supposed to enter an activation code. This technique is possible due to the fact that Base32 is constructed so that it doesn't contain visually confusing characters. For example, `1` (number one) and `I` (capital I) are confusing, so only `I` is allowed. The benefit is that the provided function can correct typed `1` and translate it to `I`.

Here's an example how to iterate over the string and validate it character by character:

```kotlin
/// Returns corrected character or null in case of error.
fun validateTypedCharacters(input: String): String? {
    val length = input.length
    val output = StringBuilder(length)
    var offset = 0
    while (offset < length) {
        val codepoint = input.codePointAt(offset)
        offset += Character.charCount(codepoint)
        val corrected = ActivationCodeUtil.validateAndCorrectTypedCharacter(codepoint)
        if (corrected == 0) {
            return null
        }
        // Character.isBmpCodePoint(corrected) is always true
        output.append(corrected.toChar())
    }
    return output.toString()
}

// validateTypedCharacter("v1") == "VI"
// validateTypedCharacter("9") == null
```

## Read Next

- [Requesting Device Activation Status](Android-Requesting-Device-Activation-Status.md)
