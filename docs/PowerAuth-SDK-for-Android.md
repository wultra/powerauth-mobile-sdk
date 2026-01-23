# PowerAuth Mobile SDK for Android

<!-- begin remove -->
## Table of Contents

- [SDK Installation](#installation)
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
  - [Symmetric Multi-Factor Authentication Code](#symmetric-multi-factor-authentication-code)
  - [Asymmetric Private Key Signature](#asymmetric-private-key-signature)
  - [Symmetric Offline Multi-Factor Authentication Code](#symmetric-offline-multi-factor-authentication-code)
  - [Producing Signed JWT with Provided Claims](#producing-signed-jwt-with-provided-claims)
  - [Verify Server-Signed Data](#verify-server-signed-data)
- [Password Change](#password-change)
- [Working with passwords securely](#working-with-passwords-securely)
- [Working with sensitive data](#working-with-sensitive-data)
- [Biometric Authentication Setup](#biometric-authentication-setup)
- [Device Activation Removal](#activation-removal)
- [End-To-End Encryption](#end-to-end-encryption)
- [Secure Vault](#secure-vault)
- [Token-Based Authentication](#token-based-authentication)
- [External Encryption Key](#external-encryption-key)
- [Synchronized Time](#synchronized-time)
- [Common SDK Tasks](#common-sdk-tasks)
- [Additional Features](#additional-features)
  - [Obtaining User's Claims](#obtaining-users-claims)
  - [Password Strength Indicator](#password-strength-indicator)
  - [Debug Build Detection](#debug-build-detection)
  - [Request Interceptors](#request-interceptors)
<!-- end -->

## Installation

To get PowerAuth SDK for Android up and running in your app, add the following dependency in your `gradle.build` file:

```gradle
repositories {
    mavenCentral() // if not defined elsewhere...
}

dependencies {
    compile 'com.wultra.android.powerauth:powerauth-sdk:1.x.y'
}
```

Note that this documentation is using version `1.x.y` as an example. You can find the latest version in our [List of Releases](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Releases.md). The Android Studio IDE can also find and offer updates for your application's dependencies.

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

## Configuration

In order to be able to configure your `PowerAuthSDK` instance, you need the following values from the PowerAuth Server:

- `MOBILE_SDK_CONFIG` - String that contains cryptographic configuration.

You also need to specify your instance ID (by default, this can be for example an app package name). This is because one application may use more than one custom instance of `PowerAuthSDK`, and the identifier is the way to distinguish these instances while working with Keychain data.

Finally, you need to know the location of your [PowerAuth Standard RESTful API](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Standard-RESTful-API.md) endpoints. That path should contain everything that goes before the `/pa/**` prefix of the API endpoints.

To sum it up, in order to configure the `PowerAuthSDK` default instance, add the following code to your application main activity `onCreate()` method:

```kotlin
val INSTANCE_ID = applicationContext.packageName
val MOBILE_SDK_CONFIG = "MTIzNDU2Nz...jc4OTAxMg=="
val API_SERVER = "https://<your-domain>/enrollment-server"

try {
    val configuration = PowerAuthConfiguration.Builder(
        INSTANCE_ID,
        API_SERVER,
        MOBILE_SDK_CONFIG)
        .build()
    val powerAuthSDK = PowerAuthSDK.Builder(configuration)
        .build(applicationContext)
} catch (exception: PowerAuthErrorException) {
    // Failed to construct `PowerAuthSDK` due to insufficient keychain protection.
    // (See next chapter for details)
}
```

If you don't provide the application's context to the `build()` method, then PowerAuthSDK will fail to register its components for the application's lifecycle callbacks. To fix this, please use the following code in your application's `onCreate()` method:

```kotlin
PowerAuthAppLifecycleListener.getInstance().registerForActivityLifecycleCallbacks(this) // "this" is Application
```


### Additional configuration

The `PowerAuthConfiguration.Builder` class provides the following additional methods that can alter the configuration:

- `offlineAuthenticationCodeComponentLength()` - Alters the default component length for the [offline authentication code](#symmetric-offline-multi-factor-authentication-code). The values between 4 and 8 are allowed. The default value is 8.
- `externalEncryptionKey()` - See [External Encryption Key](#external-encryption-key) chapter for more details.
- `disableAutomaticProtocolUpgrade()` - Disables the automatic protocol upgrade. This option should be used only for debugging purposes.

### Biometric configuration

The `PowerAuthBiometricConfiguration.Builder` class contains biometric configuration for `PowerAuthSDK` class. It has the following configuration properties:

- `invalidateBiometricFactorAfterChange()` - Function specifies whether the biometric factor key is invalidated if fingers are added or removed, or if the user re-enrolls for face. See [Biometry Factor-Related Key Lifetime](#biometry-factor-related-key-lifetime) chapter for more details.
- `confirmBiometricAuthentication()` - Function specifies whether the user's confirmation will be required after the successful biometric authentication. See [Biometric Authentication Confirmation](#biometric-authentication-confirmation) chapter for more details.
- `authenticateOnBiometricKeySetup()` - Function specifies whether setup for biometric factor always require a biometric authentication. See [Enable Biometric Authentication](#enable-biometric-authentication) chapter for more details.
- `enableFallbackToSharedBiometryKey()` - Function specifies whether `PowerAuthSDK` instance should also do additional lookup for a legacy biometric key, previously shared between multiple `PowerAuthSDK` object instances. The default value is `true` and the fallback is enabled. If your application is using multiple `PowerAuthSDK` instances, then it's recommended to set this option to `false` to avoid use of the shared key between such instances.


### HTTP client configuration

The `PowerAuthClientConfiguration.Builder` class contains configuration for a HTTP client used internally by `PowerAuthSDK` class. It has the following configuration properties:

- `timeouts()` - Function specifies connection and read timeout in milliseconds.
- `allowUnsecuredConnection()` - Enables or disables connection to unsecured servers. Do not use this option in the production build of your application. 
- `clientValidationStrategy()` - Specifies TLS client validation strategy. See [Working with Invalid SSL Certificates](#working-with-invalid-ssl-certificates) for more details.
- `requestInterceptor()` - Adds a [request interceptor](#request-interceptors) used by the client before the request is executed.
- `userAgent()` - Specifies value for User-Agent HTTP request header. See [Custom User-Agent](#custom-user-agent) chapter for more details.

### Keychain configuration

The `PowerAuthKeychainConfiguration.Builder` class contains configuration for a keychain-based storage used by `PowerAuthSDK` class internally. The configuration contains the following properties:

- `minimalRequiredKeychainProtection()` - Function specifies minimal required keychain protection level that must be supported on the current device. See [Activation Data Protection](#activation-data-protection) chapter for more details.

The following properties are also available for configuration but are not recommended to be altered under typical circumstances, as changing them may impact the library’s stability or intended behavior:

- `keychainStatusId()` - Function specifies name of the Keychain file used for storing the status information.
- `keychainBiometryId()` - Function specifies name of the Keychain file used for storing the biometry key information.
- `keychainTokenStoreId()` - Function specifies name of the Keychain file used for storing the access tokens.
- `keychainKeyBiometry()` - Function specifies name of the key to the biometry Keychain to store biometry-factor protection key.

The following properties are deprecated and moved to [Biometric Configuration](#biometric-configuration) class:

- `linkBiometricItemsToCurrentSet()` -  Function specifies whether the item protected with the biometry is invalidated if fingers are added or removed, or if the user re-enrolls for face. See [Biometry Factor-Related Key Lifetime](#biometry-factor-related-key-lifetime) chapter for more details.
- `confirmBiometricAuthentication()` - Function specifies whether the user's confirmation will be required after the successful biometric authentication. See [Biometric Authentication Confirmation](#biometric-authentication-confirmation) chapter for more details.
- `authenticateOnBiometricKeySetup()` - Function specifies whether biometric key setup always require a biometric authentication. See [Enable Biometric Authentication](#enable-biometric-authentication) chapter for more details.
- `enableFallbackToSharedBiometryKey()` - Function specifies whether `PowerAuthSDK` instance should also do additional lookup for a legacy biometric key, previously shared between multiple PowerAuthSDK object instances. The default value is `true` and the fallback is enabled. If your application is using multiple `PowerAuthSDK` instances, then it's recommended to set this option to `false` to avoid use of the shared key between such instances.

### Activation Data Protection

By default, the PowerAuth Mobile SDK for Android encrypts the local activation data with a symmetric key generated by the Android KeyStore on Android 6 and newer devices. On older devices, or if the device has an unreliable KeyStore implementation, then the fallback to unencrypted storage, based on private [SharedPreferences](https://developer.android.com/reference/android/content/SharedPreferences) is used. If your application requires a higher level of activation data protection, then you can enforce the level of protection in `PowerAuthKeychainConfiguration`:

```kotlin
try {
    val keychainConfig = PowerAuthKeychainConfiguration.Builder()
        .minimalRequiredKeychainProtection(KeychainProtection.HARDWARE)
        .build()
    // Apply keychain configuration
    val powerAuthSDK = PowerAuthSDK.Builder(configuration)
        .keychainConfiguration(keychainConfig)
        .build(context)
} catch (e: PowerAuthErrorException) {
    // Failed to construct `PowerAuthSDK` due to insufficient keychain protection.
}
```

You can also determine the level of keychain protection before `PowerAuthSDK` object creation by calling:

```kotlin
val keychainProtectionLevel = KeychainFactory.getKeychainProtectionSupportedOnDevice(context)
```

The following levels of keychain protection are defined:

- `NONE` - The content of the keychain is not encrypted and therefore not protected. This level of protection is typically reported on devices older than Android Marshmallow, or in case the device has faulty KeyStore implementation.

- `SOFTWARE` - The content of the keychain is encrypted with a key generated by Android KeyStore, but the key is protected only on the operating system level. The security of the key material relies solely on software measures, which means that a compromise of the Android OS (such as a "root" exploit) might up revealing this key.

- `HARDWARE` - The content of the keychain is encrypted with a key generated by Android KeyStore and the key is stored and managed by [Trusted Execution Environment](https://en.wikipedia.org/wiki/Trusted_execution_environment).

- `STRONGBOX` - The content of the keychain is encrypted with a key generated by Android KeyStore and the key is stored inside of Secure Element (e.g. StrongBox). This is the highest level of Keychain protection currently available, but not enabled by default. See [note below](#strongbox-support-note).

Be aware, that enforcing the required level of protection must be properly reflected in your application's user interface. That means that you should inform the user in case the device has insufficient capabilities to run your application securely.

#### StrongBox Support Note

The StrongBox-backed keys are by default turned off due to poor reliability and low performance of StrongBox implementations on the current Android devices. If you want to turn support on in your application, then use the following code at your application's startup:

```kotlin
try {
    KeychainFactory.setStrongBoxEnabled(context, true)
} catch (e: PowerAuthErrorException) {
    // You must alter the configuration before any keychain is accessed.
    // Basically, you should not create any PowerAuthSDK instance before the change.
}
```

## Activation

After you configure the SDK instance, you are ready to make your first activation.

### Activation via Activation Code

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

#### Additional Activation OTP

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

### Activation via OpenID Connect

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

### Activation via Custom Credentials

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

### Customize Activation

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

### Persisting Activation Data

After you create an activation using one of the methods mentioned above, you need to persist the activation - to use provided user credentials to store the activation data on the device. Use the following code to do this.

```kotlin
// Persist activation using given PIN
val authentication = PowerAuthAuthentication.persistWithPassword(pin)
val cancelable = powerAuthSDK.persistActivationWithAuthentication(context, authentication, object: IPersistActivationListener {
    override fun onPersistActivationSucceeded() {
        // Success
    }

    override fun onPersistActivationFailed(error: PowerAuthErrorException) {
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

    override fun onPersistActivationFailed(error: PowerAuthErrorException) {
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

### Validating User Inputs

The mobile SDK provides a couple of functions in `ActivationCodeUtil` class, helping with user input validation. You can:

- Parse activation code when it's scanned from QR code
- Validate a whole code at once
- Auto-correct characters typed on the fly

#### Validating Scanned QR Code

To validate an activation code scanned from QR code, you can use `ActivationCodeUtil.parseFromActivationCode()` function. You have to provide the code with or without the signature part. For example:

```kotlin
val scannedCode = "VVVVV-VVVVV-VVVVV-VTFVA#aGVsbG8.....gd29ybGQ="
val code = ActivationCodeUtil.parseFromActivationCode(scannedCode);
if (code?.activationCode == null) {
    // Invalid code, QR code should contain a signature
    return;
}
```

Note that the signature is only formally validated in the function above. The actual signature verification is done in the activation process, or you can do it on your own:

```kotlin
val scannedCode = "VVVVV-VVVVV-VVVVV-VTFVA#aGVsbG8......gd29ybGQ="
val code = ActivationCodeUtil.parseFromActivationCode(scannedCode)
if (code?.activationCode == null) {
    return
}
val codeBytes = code.activationCode.toByteArray()
val signatureBytes = Base64.decode(code.activationSignature, Base64.NO_WRAP)
if (!powerAuthSDK.verifyServerSignedData(codeBytes, signatureBytes, true)) {
    // Invalid signature
}
```

#### Validating Entered Activation Code

To validate an activation code at once, you can call `ActivationCodeUtil.validateActivationCode()` function. You have to provide the code without the signature part. For example:

```kotlin
val isValid = ActivationCodeUtil.validateActivationCode("VVVVV-VVVVV-VVVVV-VTFVA")
val isInvalid = ActivationCodeUtil.validateActivationCode("VVVVV-VVVVV-VVVVV-VTFVA#aGVsbG8gd29ybGQ=")
```

If your application is using your own validation, then you should switch to functions provided by SDK. The reason for that is that since SDK `1.0.0`, all activation codes contain a checksum, so it's possible to detect mistyped characters before you start the activation. Check our [Activation Code](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Activation-Code.md) documentation for more details.

#### Auto-Correcting Typed Characters

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

## Requesting Activation Status

To obtain detailed activation status information, use the following code:

```kotlin
// Check if there is some activation on the device
if (powerAuthSDK.hasValidActivation()) {
    // If there is an activation on the device, check the status with server
    powerAuthSDK.fetchActivationStatusWithCallback(context, object: IActivationStatusListener {
        override fun onActivationStatusSucceed(status: PowerAuthActivationStatus) {
            // Activation states are explained in detail in "Activation states" chapter below
            when (status.state) {
                PowerAuthActivationState.PENDING_COMMIT ->
                    Log.i(TAG, "Waiting for commit")
                PowerAuthActivationState.ACTIVE ->
                    Log.i(TAG, "Activation is active")
                PowerAuthActivationState.BLOCKED ->
                    Log.i(TAG, "Activation is blocked")
                PowerAuthActivationState.REMOVED -> {
                    Log.i(TAG, "Activation is no longer valid")
                    powerAuthSDK.removeActivationLocal(context)
                }
                PowerAuthActivationState.DEADLOCK -> {
                    Log.i(TAG, "Activation is technically blocked")
                    powerAuthSDK.removeActivationLocal(context)
                }
                else -> Log.i(TAG, "Unknown state")
            }

            // Failed login attempts, remaining = max - current
            val currentFailCount: Int = status.failCount
            val maxAllowedFailCount: Int = status.maxFailCount
            val remainingFailCount: Int = status.remainingAttempts
            if (status.customObject != null) {
                // Custom object contains any proprietary server specific data
            }
            if (status.isProtocolUpgradeAvailable) {
                // Upgrade to new protocol is available
            }
        }

        override fun onActivationStatusFailed(t: Throwable) {
            // Network error occurred, report it to the user
        }
    })
} else {
    // No activation present on device
}
```

Note that the status fetch may fail at an unrecoverable error `PowerAuthErrorCodes.PROTOCOL_UPGRADE`, meaning that it's not possible to upgrade the PowerAuth protocol to a newer version. In this case, it's recommended to [remove the activation locally](#activation-removal).

### Activation states

This chapter explains activation states in detail. To get more information about activation lifecycle, check the [Activation States](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Activation.md#activation-states) chapter available in our [powerauth-crypto](https://github.com/wultra/powerauth-crypto) repository.

#### `PowerAuthActivationState.CREATED` 

The activation record is created using an external channel, such as the Internet banking, but the key exchange between the client and server did not happen yet. This state is never reported to the mobile client.

#### `PowerAuthActivationState.PENDING_COMMIT`

The activation record is created, and the key exchange between the client and server has already taken place, but the activation record on the server requires additional approval before it can be used. This approval is typically performed through an internet banking platform by the client or handled by an authorized representative in a back office system.

#### `PowerAuthActivationState.ACTIVE`

The activation record is created and active. It is ready to be used for typical use-cases, such as generating authentication codes.

#### `PowerAuthActivationState.BLOCKED`

The activation record is blocked and cannot be used for most use-cases, such as generating authentication codes. While it can be unblocked and activated again, the unblock process cannot be performed locally on the mobile device and requires intervention through an external system, such as internet banking or a back office platform.

#### `PowerAuthActivationState.REMOVED`

The activation record is removed and permanently blocked. It cannot be used for generating authentication codes or ever unblocked. You can inform user about this situation and remove the activation locally.

#### `PowerAuthActivationState.DEADLOCK`

The local activation is technically blocked and can no longer be used for authentication code calculations. You can inform the user about this situation and remove the activation locally.

The reason why the mobile client is no longer capable of calculating valid authentication codes is that the logical counter is out of sync between the client and the server. This may happen only if the mobile client calculates too many PowerAuth authentication codes without subsequent validation on the server. For example:

- If your application repeatedly constructs HTTP requests with a PowerAuth authentication header while the network is unreachable.
- If your application repeatedly creates authentication tokens while the network is unreachable. For example, when trying to register for push notifications in the background, without user interaction.
- If you calculate too many offline authentication codes without subsequent validation.

In rare situations, this may also happen in development or testing environments, where you’re able to restore the state of the activation on the server from a snapshot.

## Data Signing

The main feature of the PowerAuth protocol is data signing. PowerAuth has various types of signatures:

- **Symmetric Multi-Factor Authentication Code**: Suitable for most operations, such as login, new payment, or confirming changes in settings.
- **Asymmetric Private Key Signature**: Suitable for documents where a strong one-sided signature is desired.
- **Symmetric Offline Multi-Factor Authentication Code**: Suitable for very secure operations, where the signature is validated over the out-of-band channel.
- **Verify server signed data**: Suitable for receiving arbitrary data from the server.

### Symmetric Multi-Factor Authentication Code

To authenticate the request data, you need to first obtain user credentials (password, PIN code, biometric image) from the user. The task of obtaining the user credentials is used in more use-cases covered by the SDK. The core class is `PowerAuthAuthentication` that holds information about the used authentication factors:

```kotlin
// 1FA authentication code, uses device related key only.
val oneFactor = PowerAuthAuthentication.possession()

// 2FA authentication code - uses device related key and user PIN code.
val twoFactorPassword = PowerAuthAuthentication.possessionWithPassword("1234")

// 2FA authentication code, uses biometry factor-related key as a 2nd. factor.
// To obtain biometryFactorRelatedKey see "Fetching the Biometry Factor-Related Key for Authentication" chapter.
val twoFactorBiometry = PowerAuthAuthentication.possessionWithBiometry(biometryFactorRelatedKey)
```

When signing `POST`, `PUT` or `DELETE` requests, use request body bytes (UTF-8) as request data and the following code:

```kotlin
// 2FA authentication code - uses device related key and user PIN code
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")

// Compute authentication header for POST call with provided data made to URI with custom identifier "/payment/create"
try {
    val header = powerAuthSDK.authenticationHeaderForRequestWithBody(context, authentication, "POST", "/payment/create", requestBodyBytes)
    val httpHeaderKey = header.getKey()
    val httpHeaderValue = header.getValue()
} catch (e: PowerAuthErrorException) {
    // Handle error
}
```

When signing `GET` or `DELETE` request with query parameters, use the following code:

```kotlin
// 2FA authentication code - uses device-related key and user PIN code
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")

// Compute authentication header for GET call with provided query parameters made to URI with custom identifier "/payment/create"
val params = mapOf("param1" to "value1", "param2" to "value2")
try {
    val header = powerAuthSDK.authenticationHeaderForRequestWithParams(context, authentication, "GET", "/payment/create", params)
    val httpHeaderKey = header.getKey()
    val httpHeaderValue = header.getValue()
} catch (e: PowerAuthErrorException) {
    // Handle error
}
```

The result of the operation is appropriate HTTP header - you are responsible for hooking up the header value in your request correctly. The process with libraries like `OkHttp` goes like this:

```kotlin
// Prepare the request builder
val builder: Request.Builder = Builder().url(endpoint)

// Compute PowerAuth authentication header
try {
    val header = powerAuthSDK.authenticationHeaderForRequestWithBody(context, authentication, "POST", "/session/login", jsonBody)
    // Add HTTP header in the request builder
    builder.header(header.getKey(), header.getValue())
} catch (e: PowerAuthErrorException) {
    // Handle error
}

// Build the request, send it, and process the response...
// ...
```

#### Request Synchronization

It is recommended that your application executes only one signed request at the time. The reason for that is that our scheme for authentication codes is using a counter as a representation of logical time. In other words, the order of request validation on the server is very important. If you issue more than one signed request at the same time, then the order is not guaranteed, and therefore one of the requests may fail. On top of that, Mobile SDK itself is using this type of authentication for its own purposes. For example, if you ask for token, then the SDK is using authenticated request to obtain the token's data. To deal with this problem, Mobile SDK is providing a custom serial `Executor`, which can be used for signed requests execution:

```kotlin
powerAuthSDK.serialExecutor.execute {
    // Recommended practice:
    // 1. You have to calculate the PowerAuth authentication header here.
    // 2. In case that you start yet another asynchronous operation from run(),
    //    then you have to wait for that operation's execution.
}
```

### Asymmetric Private Key Signature

Asymmetric Private Key Signature uses a private key stored in the PowerAuth secure vault. In order to unlock the secure vault and retrieve the private key, the user has to first authenticate using the symmetric multi-factor authentication code with at least two factors. This mechanism protects the private key on the device - the server plays a role of a "doorkeeper" and holds the vault unlock key.

This process is completely transparent on the SDK level. To compute an asymmetric private key signature, request user credentials (password, PIN, biometric image) and use the following code:

```kotlin
// Prepare the authentication object
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")

// Get the data to be signed
val data: ByteArray = this.getMyData()

powerAuthSDK.signDataWithDevicePrivateKey(context, authentication, data, object: IDataSignatureListener {
    override fun onDataSignedSucceed(signature: ByteArray) {
        // Use data signature...
    }

    override fun onDataSignedFailed(t: Throwable) {
        // Report error
    }
})
```

### Producing Signed JWT with Provided Claims

The asymmetric private key signatures described above can be used to sign claims provided by the developer and construct a signed JWT (signed using ES256 algorithm).

```kotlin
// Construct claims array
val claims = mapOf(
    "sub" to "user-id", 
    "first_name" to "John",
    "last_name" to "Appleseed"
)

// 2FA - uses device related key and user PIN code
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")

// Unlock the secure vault, fetch the private key and perform data signing
powerAuthSDK.signJwtWithDevicePrivateKey(context, authentication, claims, object : IJwtSignatureListener {
    override fun onJwtSignatureSucceed(jwt: String) {
        // Use JWT value
    }

    override fun onJwtSignatureFailed(t: Throwable) {
        // Authentication or network error
    }
})
```

### Symmetric Offline Multi-Factor Authentication Code

This type of authentication is very similar to [Symmetric Multi-Factor Authentication Code](#symmetric-multi-factor-authentication-code) but the result is provided in the form of a simple, human-readable string (unlike the online version, where the result is an HTTP header). To calculate the code, you need a typical `PowerAuthAuthentication` object to define all required factors, nonce and data to sign. The `nonce` and `data` should also be transmitted to the application over the OOB channel (for example, by scanning a QR code). Then the authentication code calculation is straightforward:

```kotlin
// Prepare the authentication object
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")

powerAuthSDK.offlineAuthenticationCode(context, authentication, "/confirm/offline/operation", data, nonce, object: IOfflineAuthenticationCodeListener {
    override fun onOfflineAuthenticationCodeSucceed(authenticationCode: String) {
        Log.d(TAG, "Offline authentication code is: $authenticationCode")
    }

    override fun onOfflineAuthenticationCodeFailed(error: PowerAuthErrorException) {
        // Handle the error, such as biometric authentication cancel.
    }
})
```

The application has to show that calculated code to the user now, and the user has to re-type that code into the web application for the verification.

<!-- begin box info -->
You can alter the length of the code components by using `offlineAuthenticationCodeComponentLength()` function of `PowerAuthConfiguration.Builder` class.
<!-- end -->

### Verify Server-Signed Data

This task is useful whenever you need to receive arbitrary data from the server and you need to be able to verify that the server has issued the data. The PowerAuthSDK provides a high-level method for validating data and associated signature:  

```kotlin
// Validate data signed with the master server key
if (powerAuthSDK.verifyServerSignedData(data, signature, true)) {
    // data is signed with server's private master key
}
// Validate data signed with the personalized server key
if (powerAuthSDK.verifyServerSignedData(data, signature, false)) {
    // data is signed with the server's private key
}  
```

## Password Change

Since the device does not know the password and is unable to verify the password without the help of the server-side, you need to first call an endpoint that verifies an authentication code computed with the password. SDK offers two ways to do that.

The safe but typically slower way is to use the following code:

```kotlin
// Change password from "oldPassword" to "newPassword".
powerAuthSDK.changePassword(context, "oldPassword", "newPassword", object: IChangePasswordListener {
    override fun onPasswordChangeSucceed() {
        // Password was changed
    }

    override fun onPasswordChangeFailed(t: Throwable) {
        // Error occurred
    }
})
```

This method calls `/pa/v3/signature/validate` under the hood with a 2FA authentication code with provided original password to verify the password correctness.

However, using this method does not usually fit the typical UI workflow of a password change. The method may be used in cases where an old password and a new password are on a single screen, and therefore are both available at the same time. In most mobile apps, however, the user first visits a screen to enter an old password, and then (if the password is OK), the user proceeds to the two-screen flow of a new password setup (select password, confirm password). In other words, the workflow works like this:

1. Show a screen to enter an old password.
2. Check an old password on the server.
3. If the old password is OK, then let the user chose and confirm a new one.
4. Change the password by re-encrypting the activation data.

For this purpose, you can use the following code:

```kotlin
// [1] Ask for an old password
val oldPassword = "1234"

// [2] Validate password on the server
powerAuthSDK.validatePassword(context, oldPassword, object: IValidatePasswordListener {
    override fun onPasswordValid() {
        // Proceed to the new password setup
    }

    override fun onPasswordValidationFailed(t: Throwable) {
        // Retry entering an old password
    }
})

// [3] Ask for new password
val newPassword = "2468"

// [4] Change the password locally
powerAuthSDK.changePasswordUnsafe(oldPassword, newPassword)
```

<!-- begin box warning -->
**Now, beware!** Since the device does not know the actual old password, you need to make sure that the old password is validated before you use it in `unsafeChangePassword`. In case you provide the wrong old password, it will be used to decrypt the original data, and these data will be encrypted using a new password. As a result, the activation data will be broken and irreversibly lost.
<!-- end -->


## Working with passwords securely

PowerAuth mobile SDK uses the `io.getlime.security.powerauth.core.Password` object behind the scenes, to store the user's password or PIN securely. The object automatically wipes out the plaintext password on its destroy, so there are no traces of sensitive data left in the memory. You can easily enhance your application's runtime security by adopting this object in your code and this chapter explains in detail how to do it.

### Problem explanation

If you store the user's password in a simple string, there is a high probability that the content of the string will remain in the memory until the same region is reused by the underlying memory allocator. This is because the general memory allocator doesn't clean up the region of memory being freed. It just updates its linked-list of free memory regions for future reuse, so the content of the allocated object typically remains intact. This has the following implications for your application:

- If your application is using a system keyboard to enter the password or PIN, then the sensitive data will remain in memory in multiple copies for a while. 

- If the device's memory is not stressed enough, then the application may remain in memory active for days.

The situation that the user's password stays in memory for days may be critical in situations when the attacker has the device in possession. For example, if the device is lost or is in a repair shop. To minimize the risks, the `Password` object does the following things:

- Always keeps the user's password scrambled with random data, so it cannot be easily found by simple string search. The password in plaintext is revealed only for a short and well-defined time when it's needed for the cryptographic operation.

- Always clear buffer with the sensitive data before the object's destruction.

- Doesn't provide a simple interface to reveal the password in plaintext<sup>1)</sup> and therefore it minimizes the risks of revealing the password by accident (like printing it to the log).

<!-- begin box info -->
**Note 1:** There's a `validatePasswordComplexity()` function that reveals the password in plaintext for a limited time for complexity validation purposes. The straightforward naming of the function allows you to find all its usages in your code and properly validate all code paths.
<!-- end -->

### Special password object usage

PowerAuth mobile SDK allows you to use both strings and special password objects at input, so it's up to you which way fits best for your purposes. For simplicity, this documentation uses strings for the passwords, but all code examples can be changed to utilize the `Password` object as well. For example, this is the modified code for [Password Change](#password-change):

```kotlin
// Change password from "oldPassword" to "newPassword".
val oldPass = Password("oldPassword")
val newPass = Password("newPassword")
powerAuthSDK.changePassword(context, oldPass, newPass, object: IChangePasswordListener {
    override fun onPasswordChangeSucceed() {
        // Password was changed
    }

    override fun onPasswordChangeFailed(t: Throwable) {
        // Error occurred
    }
})
```

### Entering PIN

If your application is using a system numeric keyboard to enter the user's PIN then you can migrate to the `Password` object right now. We recommend you do the following things:

- Implement your own PIN keyboard UI

- Make sure that the password object is allocated and referenced only in the PIN keyboard controller and is deallocated when the user leaves the controller.

- Use the `Password()` object that allows you to manipulate the content of the PIN 

Here's the simple pseudo-controller example:

```kotlin
class EnterPinScene(val desiredPinLength: Int = 4) {

    private var pinInstance: Password? = null
    private val pin: Password get() = pinInstance ?: throw IllegalStateException()

    fun onEnterScene() {
        // Allocate password when entering to the scene.
        // Constructor with no parameters creates a mutable Password.
        pinInstance = Password()
    }

    fun onLeaveScene() {
        // Dereference and destroy the password object, when the user is leaving
        // the scene to safely wipe the content out of the memory.
        //
        // Make sure that this is done only after PowerAuth SDK finishes all operations
        // started with this object at input.
        // 
        // Note that IllegalStateException is raised if you use Password object after its destroy.
        pinInstance?.destroy()
        pinInstance = null
    }

    fun onDeleteButtonAction() {
        pin.removeLastCharacter()
    }

    fun onPinButtonAction(pinCharacter: Char) {
        // Mutable password works with Unicode scalars, this is the example
        // that works with an arbitrary character up to code point 0xFFFF.
        // To add an arbitrary Unicode character, you need to convert it to code point first.
        // See https://stackoverflow.com/questions/9834964/char-to-unicode-more-than-uffff-in-java
        pin.addCharacter(pinCharacter.code)
        if (pin.length() == desiredPinLength) {
            onContinueAction(pin)
        }
    }

    fun onPinButtonActionSimplified(pinIndex: Int) {
        // This is a simplified version of onPinButtonAction() that use
        // simple PIN button index as input.
        if (pinIndex < 0 || pinIndex > 9) {
            throw IllegalArgumentException("Wrong PIN index")
        }
        // You don't need to add 48 (code for character "0") to the index, 
        // unless your previous implementation was using number characters.
        pin.addCharacter(48 + pinIndex)
        if (pin.length() == desiredPinLength) {
            onContinueAction(pin)
        }
    }

    fun onContinueAction(pin: Password) {
        // Do something with the entered pin...
    }
}
```

### Entering arbitrary password

Unfortunately, there's no simple solution for this scenario. It's quite difficult to re-implement the whole keyboard on your own, so we recommend you keep using the system keyboard. You can still create the `Password` object from an already entered string:

```kotlin
val passwordString = "nbusr123"
val password = Password(passwordString)
```

### Create a password from the data

In case that passphrase is somehow created externally in the form of an array of bytes, then you can instantiate it from the `Data` object directly:

```kotlin
val passwordData = Base64.decode("bmJ1c3IxMjMK", Base64.NO_WRAP)
val password = Password(passwordData)
```


### Compare two passwords

To compare two passwords, use the `isEqual(to:)` method:

```kotlin
val password1 = Password("1234")
val password2 = Password("Hello")
val password3 = Password()
password3.addCharacter(0x31)
password3.addCharacter(0x32)
password3.addCharacter(0x33)
password3.addCharacter(0x34)
print("${password1.isEqualToPassword(password2)}")  // false
print("${password1 == password3}")                  // true
```

### Validate password complexity

The `Password` object doesn't provide functions that validate password complexity, but allows you to implement such functionality on your own:

```kotlin
enum class PasswordComplexity(val value: Int) {
    WEAK(0),
    GOOD(1),
    STRONG(2);

    companion object {
        fun fromInt(value: Int): PasswordComplexity = values().first { it.value == value }
    }
}

// This is an actual complexity validator that also accepts ByteArray at its input. You should avoid
// converting provided bytes into String or copy passphrase to another byte array to minimize risk
// of leaking the password in memory.
fun superPasswordValidator(password: ByteArray): PasswordComplexity {
    // This is just an example, please do not use such trivial validation in your
    // production application :)
    if (password.size < 4) {
        return PasswordComplexity.WEAK
    } else if (password.size < 8) {
        return PasswordComplexity.GOOD
    }
    return PasswordComplexity.STRONG
}

// Convenient wrapper to validatePasswordComplexity() method
fun Password.validateComplexity(): PasswordComplexity {
    val resultValue = validatePasswordComplexity { passwordBytes ->
        superPasswordValidator(passwordBytes).value
    }
    return PasswordComplexity.fromInt(resultValue)
}
```

<!-- begin box info -->
You can use our [Passphrase meter](https://github.com/wultra/passphrase-meter) library as a proper password validation solution.
<!-- end -->


## Working with sensitive data

The PowerAuth mobile SDK is using `SecureData` class for manage the cryptographically sensitive data, such as encryption keys. You can encounter this class in several public API functions, such as functions for managing an [external encryption key](#external-encryption-key). This chapter explains how to use the `SecureData` object properly.

### Create instance of `SecureData`

If you need to provide cryptographically sensitive key material to PowerAuth mobile SDK, then use the following code:

```kotlin
val yourKey = "nbuSR123nbuSR123".toByteArray()
val secureData = SecureData.copy(yourKey)
```

The `secureData` object will keep copy of bytes. In case you also wants to erase also the content of the source array, then you can use an alternative construction:

```kotlin
val yourKey = "nbuSR123nbuSR123".toByteArray()
val secureData = SecureData.copyAndClearSource(yourKey)
```

Finally, if you're sure that no other object retains reference to the byte array (for example, if it's returned as a result of encrypt or decrypt function), then you can use the following construction:

```kotlin
val yourKey = "nbuSR123nbuSR123".toByteArray()
val secureData = SecureData.capture(yourKey)
```

### Using instance of `SecureData`

To get reference to stored bytes, use the following code:

```swift
func processSecureData(secureData: SecureData) {
    doSomethingWitBytes(secureData.sensitiveData)
}
```

<!-- begin box warning -->
Be aware that you should not keep the reference to provided byte array. If you need to keep the bytes longer, then keep the reference to `SecureData` instance, or make your own copy of bytes, returned in `sensitiveData` property.
<!-- end -->



## Biometric Authentication Setup

PowerAuth SDK for Android provides an abstraction on top of the base Biometric Authentication support. While the authentication / data signing itself is handled using the `PowerAuthAuthentication` object used in [regular request signing](#data-signing), other biometry-related processes require their own API.

### Check Biometric Authentication Status

You have to check for Biometric Authentication on three levels:

- **System Availability**: If a biometric scanner is present on the system.
- **Activation Availability**: If biometry factor data are available for given activation.
- **Application Availability**: If the user decides to use biometric authentication for the given app. _(optional)_

PowerAuth SDK for Android provides code for the first and second of these checks.

To check if you can use the biometric authentication, use our helper class:

```kotlin
// This method is equivalent to `BiometricManager.canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS`.
// Use it to check if the biometric authentication can be used at the moment.
val isBiometricAuthAvailable = BiometricAuthentication.isBiometricAuthenticationAvailable(context)

// For more fine-grained control about the actual biometric authentication status,
// you may use the following code:
when (BiometricAuthentication.canAuthenticate(context)) {
    BiometricStatus.OK ->
        print("Everything is OK")
    BiometricStatus.NOT_SUPPORTED ->
        print("device's hardware doesn't support biometry")
    BiometricStatus.NOT_ENROLLED ->
        print("there's no biometry data enrolled on the device")
    BiometricStatus.NOT_AVAILABLE ->
        print("The biometric authentication is not available at this time. Retry later.")
}

// If you want to adjust localized strings or icons presented to the user,
// you can use the following code to determine the type of biometry available
// on the system:
when (BiometricAuthentication.getBiometryType(context)) {
    BiometryType.NONE ->
        print("Biometry is not supported on the system.")
    BiometryType.GENERIC ->
        // It's not possible to determine the exact type of biometry.
        // This occurs on Android 10+ systems when the device supports
        // more than one type of biometric authentication. In this case,
        // you should use generic terms in your UI, such as "Authenticate with biometry".
        // This issue can also arise on devices that support a new type of biometry
        // sensor, or on older, malfunctioning devices that fail to declare 
        // support for FEATURE_FINGERPRINT.
        print("Biometry type is GENERIC")
    BiometryType.FINGERPRINT ->
        print("Fingerprint scanner is present on the device.")
    BiometryType.FACE ->
        print("Face scanner is present on the device.")
    BiometryType.IRIS ->
        print("Iris scanner is present on the device.")
}
```

To check if a given activation has biometry factor-related data available, use the following code:

```kotlin
// Does activation have biometric factor-related data in place?
val hasBiometryFactor = powerAuthSDK.hasBiometryFactor(context)
```

The last check is fully under your control. By keeping the biometric settings flag, for example, a `BOOL` in `SharedPreferences`, you can show the user an expected biometric authentication status (in a disabled state, though) even in the case biometric authentication is not enabled or when no fingers are enrolled on the device.

### Enable Biometric Authentication

In case an activation does not yet have biometry-related factor data, and you would like to enable biometric authentication support, the device must first retrieve the original private key from the secure vault for key derivation. As a result, you have to use a successful 2FA with a password to enable biometric authentication support.

Use the following code to enable biometric authentication using biometric authentication:

```kotlin
// Prepare biometric prompt.
val biometricPrompt = PowerAuthBiometricPrompt.Builder(parentFragment)  // You can also use fragment activity in the constructor
                        .setTitle("Enable Biometric Authentication")
                        .setDescription("To enable biometric authentication, use the biometric sensor on your device.")
                        .build()
// Establish biometric data using the provided password
powerAuthSDK.addBiometryFactor(context, "1234", biometricPrompt, object: IAddBiometryFactorListener {
    override fun onAddBiometryFactorSucceed() {
        // Everything went OK, biometric authentication is ready to be used
    }

    override fun onAddBiometryFactorFailed(error: PowerAuthErrorException) {
        // Error occurred, report it to the user
    }
})
```

By default, PowerAuth SDK asks the user to authenticate with the biometric sensor also during the setup procedure (or during the [activation persist](#persisting-activation-data)). To alter this behavior, use the following code to change the `PowerAuthBiometricConfiguration` provided to the `PowerAuthSDK` instance:

```kotlin
val biometricConfig = PowerAuthBiometricConfiguration.Builder()
    .authenticateOnBiometricKeySetup(false)
    .build()
// Apply keychain configuration
val powerAuthSDK = PowerAuthSDK.Builder(configuration)
    .biometricConfiguration(biometricConfig)
    .build(getApplicationContext())
```

<!-- begin box info -->
Note that the RSA key pair is internally generated for the configuration above. That may take more time on older devices than the default configuration. Your application should display a waiting indicator on its own because SDK doesn't display an authentication dialog during the key-pair generation.
<!-- end -->

If the configuration above is applied, then you can use a "dummy" biometric prompt to simplify your biometric setup code:

```kotlin
// Prepare biometric prompt.
val biometricPrompt = PowerAuthBiometricPrompt.noPromptForBiometricKeySetup(parentFragment)
// Establish biometric data using the provided password
powerAuthSDK.addBiometryFactor(context, "1234", biometricPrompt, object: IAddBiometryFactorListener {
    // listener is the same as in previous example
})
```

### Disable Biometric Authentication

To remove biometry-related factor data used by biometric authentication use the following code:

```kotlin
powerAuthSDK.removeBiometryFactor(context, object: IRemoveBiometryFactorListener {
    override fun onRemoveBiometryFactorSucceed() {
        // Everything went OK, biometric authentication is ready to be used
    }

    override fun onRemoveBiometryFactorFailed(error: PowerAuthErrorException) {
        // Error occurred, report it to the user
    }
})
```

### Fetching the Biometry Factor-Related Key for Authentication

To obtain an encrypted biometry factor-related key for authentication, call the following code:

```kotlin
// Prepare biometric prompt data
val biometricPrompt = PowerAuthBiometricPrompt.Builder(parentFragment)  // You can also use fragment activity in the constructor
                        .setTitle("Sign in")
                        .setDescription("Use the biometric sensor on your device to sign in.")
                        .build()
// Authenticate user with biometry and obtain encrypted biometry factor related key.
powerAuthSDK.authenticateUsingBiometrics(context, biometricPrompt, object: IAuthenticateWithBiometricsListener {
    override fun onBiometricDialogCancelled(userCancel: Boolean) {
        // User or system canceled the operation
    }

    override fun onBiometricDialogSuccess(authentication: PowerAuthAuthentication) {
        // User authenticated to use the provided authentication object for other tasks.
    }

    override fun onBiometricDialogFailed(error: PowerAuthErrorException) {
        // Biometric authentication failed
        val biometricErrorInfo = error.additionalInformation as? BiometricErrorInfo
        if (biometricErrorInfo != null) {
            if (biometricErrorInfo.isErrorPresentationRequired) {
                // The application should present the reason for the biometric authentication failure to the user.
                //
                // If you don't disable the error dialog provided by the PowerAuth mobile SDK, then this may happen
                // only when you try to use the biometric authentication while the biometric factor is not configured
                // in the PowerAuthSDK instance.
                val localizedMessage = biometricErrorInfo.getLocalizedErrorMessage(context, null)
            }
        } else {
          // Other reasons for failure
        }
    }
})
```

<!-- begin box warning -->
Disable all interactive UI elements while biometric authentication is in progress. After you call `authenticateUsingBiometrics()`, display a non-interactive “Verifying…” (or similar) progress state and do not accept user input until the SDK callback fires.

Why: Once the system biometric prompt is dismissed, your app regains focus before the PowerAuth SDK finishes its post-authentication cryptographic work on a background thread. During this brief window, your UI is visible but the authentication result is not ready. If you re-enable buttons or accept gestures too early, the user could trigger actions that assume authentication succeeded (or failed) prematurely. Wait for the callback, then update the UI based on the actual result.
<!-- end -->

<!-- begin box warning -->
Note that if the biometric authentication fails with too many attempts in a row (e.g. biometry is temporarily or permanently locked out), then PowerAuth SDK will generate an invalid biometry factor related key, and the success is reported. This is an intended behavior and as a result, it typically leads to unsuccessful authentication on the server and an increased counter of failed attempts. The purpose of this is to limit the number of attempts for attackers to deceive the biometry sensor.
<!-- end -->

### Facial Biometrics on Android

Currently, facial authentication only works with several Android device models. This is because to implement facial authentication securely, the PowerAuth SDK needs to protect the biometry-related key in the Android Keystore with a biometric sensor. This type of secure storage is only supported on devices with the `BIOMETRIC_STRONG (class 3)` sensor type, as explained in the official documentation:

- https://source.android.com/docs/security/features/biometric

The Android source codes contain a list of devices with strong biometry support.

- [biometric/biometric/src/main/res/values/devices.xml](https://cs.android.com/androidx/platform/frameworks/support/+/androidx-main:biometric/biometric/src/main/res/values/devices.xml;l=81)

### Biometry Factor-Related Key Lifetime

By default, the biometry factor-related key is invalidated after the biometry enrolled in the system is changed. For example, if the user adds or removes the finger or enrolls with a new face, then the biometry factor-related key is no longer available for the signing operation. To change this behavior, you have to provide the `PowerAuthBiometricConfiguration` object with the `invalidateBiometricFactorAfterChange` parameter set to `false` and use that configuration for the `PowerAuthSDK` instance construction:

```kotlin
// Use false for the 'invalidateBiometricFactorAfterChange' parameter.
val biometricConfig = PowerAuthBiometricConfiguration.Builder()
    .invalidateBiometricFactorAfterChange(false)
    .build()
// Apply keychain configuration
val powerAuthSDK = PowerAuthSDK.Builder(configuration)
    .biometricConfiguration(biometricConfig)
    .build(getApplicationContext())
```

Be aware that the configuration above is effective only for the new keys. So, if your application is already using the biometry factor-related key with a different configuration, then the configuration change doesn't change the existing key. You have to [disable](#disable-biometric-authentication) and [enable](#enable-biometric-authentication) biometry to apply the change.

### Biometric Authentication Details

The `BiometricAuthentication` class is a high-level interface that provides interfaces related to biometric authentication for the SDK or for application purposes. The class hides all technical details, so it can be safely used also on systems that don't provide biometric interfaces, or if the system has no biometric sensor available. The implementation under the hood uses `androidx.biometric.BiometricPrompt` and `androidx.biometric.BiometricManager` classes.

#### Customize Biometric Dialog Resources 

To customize the strings used in biometric authentication, you can use `BiometricDialogResources` in the following manner:

```kotlin
// Prepare new strings, colors, etc...
val newStrings = BiometricDialogResources.Strings(... constructor with string ids ...)

// Build new resources object.
// If you omit some custom resources object, then the Builder will replace that with resources bundled in SDK.
val resources = BiometricDialogResources.Builder()
    .setStrings(newStrings)
    .build()

// Set resources to BiometricAuthentication
BiometricAuthentication.setBiometricDialogResources(resources)
```

#### Disable Error Dialog After Failed Biometry

If you prefer not to allow the PowerAuth mobile SDK to display its own error dialog, you can disable this feature globally. In this case, your application will need to handle all error situations through its own user interface. Use the following code to disable the error dialog:

```kotlin
BiometricAuthentication.setBiometricErrorDialogDisabled(true)
```

When the error dialog is disabled, your application should inform the user of the reason for the failure. Handling this might be somewhat tricky because there are situations where the biometric authentication dialog is not displayed at all, and the failure is reported directly to the application. To address this, you can use the `BiometricErrorInfo` class, which is associated with the reported `PowerAuthErrorException`. The code snippet below outlines how to determine the situation:

```kotlin
// Prepare biometric prompt data
val biometricPrompt = PowerAuthBiometricPrompt.Builder(parentFragment)  // You can also use fragment activity in the constructor
                        .setTitle("Sign in")
                        .setDescription("Use the biometric sensor on your device to sign in.")
                        .build()
// Authenticate user with biometry and obtain encrypted biometry factor related key.
powerAuthSDK.authenticateUsingBiometrics(context, biometricPrompt, object: IAuthenticateWithBiometricsListener {
    override fun onBiometricDialogCancelled(userCancel: Boolean) {
        // User or system canceled the operation
    }

    override fun onBiometricDialogSuccess(authentication: PowerAuthAuthentication) {
        // Success
    }

    override fun onBiometricDialogFailed(error: PowerAuthErrorException) {
        val biometricErrorInfo = error.additionalInformation as? BiometricErrorInfo
        if (biometricErrorInfo != null) {
            if (biometricErrorInfo.isErrorPresentationRequired) {
                // Application should present the reason of biometric authentication failure to the user
                val localizedMessage = biometricErrorInfo.getLocalizedErrorMessage(context, null)
            }
        } else {
            // Other reasons for failure
        }
    }
})
```

<!-- begin box info -->
Note that you still should [Customize Biometric Dialog Resources](#customize-biometric-dialog-resources) to get a proper localized error message.
<!-- end -->

#### Biometric Authentication Confirmation

On Android 10+ systems, it's possible to configure `BiometricPrompt` to ask for an additional confirmation after the user is successfully authenticated. The default behavior for PowerAuth Mobile SDK is that such confirmation is not required. To change this behavior, you have to provide the `PowerAuthBiometricConfiguration` object with the `confirmBiometricAuthentication` parameter set to `true` and use that configuration for the `PowerAuthSDK` instance construction:

```kotlin
// Use true for the 'confirmBiometricAuthentication' parameter.
val biometricConfig = PowerAuthBiometricConfiguration.Builder()
    .confirmBiometricAuthentication(true)
    .build()
// Apply keychain configuration
val powerAuthSDK = PowerAuthSDK.Builder(configuration)
    .biometricConfiguration(biometricConfig)
    .build(context)
```

## Activation Removal

You can remove activation using several ways - the choice depends on the desired behavior.

### Simple Device-Only Removal

You can clear activation data anytime from the `SharedPreferences`. The benefit of this method is that it does not require help from the server, and the user does not have to be logged in. The issue with this removal method is simple: The activation still remains active on the server side. This, however, does not have to be an issue in your case.

To remove only data related to PowerAuth SDK for Android, use the following code:

```kotlin
powerAuthSDK.removeActivationLocal(context)
```

### Removal via Authenticated Session

Suppose your server uses an authenticated session to keep the users logged in. In that case, you can combine the previous method with calling your proprietary endpoint to remove activation for the currently logged-in user. The advantage of this method is that activation does not remain active on the server. The issue is that the user has to be logged in (the session must be active and must have an activation ID stored) and that you have to publish your own method to handle this use case.

The code for this activation removal method is as follows:

```kotlin
// Use custom call to proprietary server endpoint to remove activation.
//The user must be logged in at this moment, so that the session can find
// associated activation ID
this.httpClient.post(null, "/custom/activation/remove", object: ICustomListener {
    override fun onSucceed() {
        powerAuthSDK.removeActivationLocal(context)
    }
    
    override fun onFailed(t: Throwable) {
        // Error occurred, report it to the user
    }
})
```

### Removal via Signed Request

PowerAuth Standard RESTful API has a default endpoint `/pa/v3/activation/remove` for an activation removal. This endpoint uses a authentication code verification for looking up the activation to be removed. The benefit of this method is that it is already present in both PowerAuth SDK for Android and PowerAuth Standard RESTful API - nothing has to be programmed. Also, the user does not have to be logged in to use it. However, the user has to authenticate using 2FA with either password or biometric authentication.

Use the following code for an activation removal using a signed request:

```kotlin
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")

// Remove activation using the provided authentication object
powerAuthSDK.removeActivationWithAuthentication(context, authentication, object: IActivationRemoveListener {
    override fun onActivationRemoveSucceed() {
        // OK, activation was removed
    }

    override fun onActivationRemoveFailed(t: Throwable) {
        // Report error to user
    }
})
```

## End-To-End Encryption

Currently, PowerAuth SDK supports two basic modes of end-to-end encryption:

- In an "application" scope, the encryptor can be acquired and used during the whole lifetime of the application.
- In an "activation" scope, the encryptor can be acquired only if `PowerAuthSDK` has a valid activation. The encryptor created for this mode is cryptographically bound to the parameters agreed during the activation process. You can combine this encryption with [PowerAuth Symmetric Multi-Factor Authentication Code](#symmetric-multi-factor-authentication-code) in "encrypt-then-sign" mode.


For both scenarios, you need to acquire an `CoreEncryptor` object, which will then provide an interface for the request encryption and the response decryption. The object currently provides only low-level encryption and decryption methods, so you need to implement your own JSON (de)serialization and request and response processing.

The following steps are typically required for a full E2EE request and response processing:

1. Acquire the right encryptor from the `PowerAuthSDK` instance. For example:
   ```kotlin
   // Encryptor for "application" scope.
   val cancelable = powerAuthSDK.getEncryptorForApplicationScope(object : IGetEncryptorListener {
        override fun onGetEncryptorSuccess(encryptor: CoreEncryptor) {
            // Success
        }

        override fun onGetEncryptorFailed(t: Throwable) {
            // Failure
        }
   });
   // ...or similar, for an "activation" scope.
   val cancelable = powerAuthSDK.getEncryptorForActivationScope(context, object : IGetEncryptorListener {
        override fun onGetEncryptorSuccess(encryptor: CoreEncryptor) {
            // Success
        }

        override fun onGetEncryptorFailed(t: Throwable) {
            // Failure
        }
   });
   ```

1. Serialize your request payload, if needed, into a sequence of bytes. This step typically means that you need to serialize your model object into a JSON-formatted sequence of bytes.

1. Encrypt your payload:
   ```kotlin
   val encryptedRequest = encryptor.encryptRequest(payloadData)
   ```

1. Use request body in your networking library
   ```kotlin
   val requestBody = encryptedRequest.requestBody;
   ```

1. Use the following HTTP headers (for signed requests, see note below) in your networking library:
   ```kotlin
   for (header in encryptedRequest.requestHeaders) {
        val headerName = header.key;
        val headerValue = header.value;
        // User header in your networking library
   }
   ```
   Note, that if an "activation" scoped encryptor is combined with PowerAuth Symmetric Multi-Factor Authentication Code, then this step is not required. The authentication header already contains all the information required for proper request decryption on the server.

1. Fire your HTTP request and wait for a response
   - In case that non-200 HTTP status code is received, then the error processing is identical to a standard RESTful response defined in our protocol. So, you can expect a JSON object with `"error"` and `"message"` properties in the response.

1. Decrypt the response
   ```kotlin
   val encryptedResponse = CoreEncryptedResponse(responseBody)
   val responseData = encryptor.decryptResponse(encryptedResponse)
   ```

1. And finally, you can process your received response.

As you can see, the E2EE is quite a non-trivial task. We recommend contacting us before using an application-specific E2EE. We can provide you with more support on a per-scenario basis, especially if we first understand what you are trying to achieve with end-to-end encryption in your application.


## Secure Vault

PowerAuth SDK for Android has basic support for an encrypted secure vault. At this moment, the only supported method allows your application to establish an encryption / decryption key with a given index. The index represents a "key number" - your identifier for a given key. Different business logic purposes should have encryption keys with different index values.

On the server side, all secure vault-related work is concentrated in a `/pa/v3/vault/unlock` endpoint of PowerAuth Standard RESTful API. To receive data from this response, the call must be authenticated with at least 2FA (using a password or PIN).

<!-- begin box warning -->
The secure vault mechanism does not support biometry by default. Use PIN code or password-based authentication for unlocking the secure vault, or ask your server developers to enable biometry for vault unlock call by configuring the PowerAuth Server instance.
<!-- end -->

### Obtaining Encryption Key

To obtain an encryption key with a given index, use the following code:

```kotlin
// 2FA authentication. It uses device-related key and user PIN code.
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")

// Select custom key index
val index = 1000L

// Fetch the encryption key with the given index
powerAuthSDK.fetchEncryptionKey(context, authentication, index, object: IFetchEncryptionKeyListener {
    override fun onFetchEncryptionKeySucceed(encryptionKey: SecureData) {
        // ... use the encryption key to encrypt or decrypt data
        val keyBytes = encryptionKey.sensitiveData
    }

    override fun onFetchEncryptionKeyFailed(t: Throwable) {
        // Report error
    }
})
```

## Token-Based Authentication

<!-- begin box warning -->
**WARNING:** Before you start using access tokens, please visit our [wiki page for powerauth-crypto](https://github.com/wultra/powerauth-crypto/blob/develop/docs/MAC-Token-Based-Authentication.md) for more information about this feature.
<!-- end -->

The tokens are simple, locally cached objects, producing timestamp-based authentication headers. Be aware that tokens are NOT a replacement for general PowerAuth Authentication Codes. They are helpful in situations when the codes are too heavy or too complicated for implementation. Each token has the following properties:

- It needs a PowerAuth Authentication Code for its creation (e.g., you need to provide a `PowerAuthAuthentication` object)
- It has a unique identifier on the server. This identifier is not exposed to the public API, but you can reveal that value in the debugger.
- It has a symbolic name (e.g., "MyToken") defined by the application programmer to identify already created tokens.
- It can generate timestamp-based authentication HTTP headers.
- It can be used concurrently. Token's private data doesn't change over time.
- The token is associated with the `PowerAuthSDK` instance. So, you can use the same symbolic name in multiple SDK instances, and each created token will be unique.
- Tokens are persisted in the `KeychainFactory` service and cached in the memory.
- Once the parent `PowerAuthSDK` instance loses its activation, all its tokens are removed from the local database.

### Getting Token

To get an access token, you can use the following code:

```kotlin
// 1FA authentication - uses device-related key
val authentication = PowerAuthAuthentication.possession()
val cancelableTask = powerAuthSDK.tokenStore.requestAccessToken(context, "MyToken", authentication, object: IGetTokenListener {
    override fun onGetTokenSucceeded(powerAuthToken: PowerAuthToken) {
        // the token has been successfully acquired
    }

    override fun onGetTokenFailed(throwable: Throwable) {
        // an error occurred
    }
})
```

The request is performed synchronously or asynchronously depending on whether the token is locally cached on the device. You can test this situation by calling `tokenStore.hasLocalToken(context, "MyToken")`. If the operation is asynchronous, then `requestAccessToken()` returns a cancellable task.

### Generating Authentication Header
Use the following code to generate an authentication header:

```kotlin
val task = tokenStore.generateAuthenticationHeader(context, "MyToken", object : IGenerateTokenHeaderListener {
    override fun onGenerateTokenHeaderSucceeded(header: PowerAuthHttpHeader) {
        val httpHeaderKey = header.key
        val httpHeaderValue = header.value
    }

    override fun onGenerateTokenHeaderFailed(t: Throwable) {
        // Failure
    }
})
```

Once you have a `PowerAuthToken` object, then you can use also a synchronous code to generate an authentication header:

```kotlin
try {
    val header = token.generateTokenHeader()
    val httpHeaderKey = header.key
    val httpHeaderValue = header.value
} catch (e: PowerAuthErrorException) {
    // Handle error
}
```

<!-- begin box warning -->
The synchronous example above is safe to use only if you're sure that the time is already [synchronized with the server](#synchronized-time).
<!-- end -->

### Removing Token From the Server

To remove the token from the server, you can use the following code:

```kotlin
powerAuthSDK.tokenStore.removeAccessToken(context, "MyToken", object: IRemoveTokenListener {
    override fun onRemoveTokenSucceeded() {
        Log.d(TAG, "Token has been removed")
    }

    override fun onRemoveTokenFailed(t: Throwable) {
        // handle HTTP error
    }
})
```

### Removing Token Locally

To remove the token locally, you can simply use the following code:

```kotlin
// Remove just one token
powerAuthSDK.tokenStore.removeLocalToken(context, "MyToken")
// Remove all local tokens
powerAuthSDK.tokenStore.removeAllLocalTokens(context)
```

Note that by removing tokens locally, you will lose control of the tokens stored on the server.

## External Encryption Key

The `PowerAuthSDK` allows you to specify an external encryption key (called EEK in our terminology) that can additionally protect the knowledge and the biometry factor keys. This feature is typically used to create a chain of activations where one instance of `PowerAuthSDK` is primary and unlocks access to all secondary activations.

The external encryption key has to be set before the activation is created, or can be added later. The internal state of `PowerAuthSDK` contains information that the factor keys are protected with EEK, so EEK must be known at the time of PowerAuth authentication code is calculated. You have three options on how to configure the key:

1. Assign EEK into `PowerAuthConfiguration.Builder` at the time of `PowerAuthSDK` object creation.
   - This is the most convenient way of using EEK, but the key must be known at the time of the `PowerAuthSDK` instantiation.
   - Once the `PowerAuthSDK` instance creates a new activation, then the factor keys will be automatically protected with EEK.
   
2. Use `PowerAuthSDK.setExternalEncryptionKey()` to set EEK after the `PowerAuthSDK` instance is created.
   - This is useful in case EEK is not known during the `PowerAuthSDK` instance creation.
   - You can set the key in any `PowerAuthSDK` state, but be aware that the method will fail in case the instance has a valid activation that doesn't use EEK.
   - It's safe to set the same EEK multiple times.

3. Use `PowerAuthSDK.addExternalEncryptionKey()` to add EEK and protect the factor keys in case `PowerAuthSDK` has already a valid activation.
   - This method is useful in case `PowerAuthSDK` already has a valid activation, but it doesn't use EEK yet.
   - The method automatically adds EEK into the internal configuration structure, but be aware, that all future `PowerAuthSDK` usages (e.g. after app restart) require setting EEK by configuration, or by the `setExternalEncryptionKey()` method.

You can remove EEK from an existing activation if the key is no longer required. To do this, use the `PowerAuthSDK.removeExternalEncryptionKey()` method. Be aware, that EEK must be set by configuration, or by the `setExternalEncryptionKey()` method before you call the remove method. You can also use the `PowerAuthSDK.hasExternalEncryptionKey()` function to test whether the key is already set and in use.


## Synchronized Time

The PowerAuth mobile SDK internally uses time synchronized with the PowerAuth Server for its cryptographic functions, such as [End-To-End Encryption](#end-to-end-encryption) or [Token-Based Authentication](#token-based-authentication). The synchronized time can also be beneficial for your application. For example, if you want to display a time-sensitive message or countdown to your users, you can take advantage of this service.

Use the following code to get the service responsible for the time synchronization: 

```kotlin
val timeService = powerAuthSDK.timeSynchronizationService
```

### Automatic Time Synchronization

The time is synchronized automatically in the following situations:

- After an activation is created
- After getting an activation status
- After receiving any response encrypted with our End-To-End Encryption scheme

The time synchronization is reset automatically once your application transitions from the background to the foreground.

### Manually Synchronize Time

Use the following code to synchronize the time manually:

```kotlin
val task = timeService.synchronizeTime(object: ITimeSynchronizationListener {
    override fun onTimeSynchronizationSucceeded() {
        // Synchronization succeeded
    }

    override fun onTimeSynchronizationFailed(t: Throwable) {
        // Synchronization failed
    }
})
```

### Get Synchronized Time

To get the synchronized time, use the following code:

```kotlin
if (timeService.isTimeSynchronized) {
    // get synchronized timestamp in milliseconds, since 1.1.1970
    val timestamp = timeService.currentTime
} else {
    // Time is not synchronized yet. If you call currentTime then 
    // the returned timestamp is similar to System.currentTimeMillis()
    val timestamp = timeService.currentTime
}
```

The time service provides additional information about time, such as how precisely the time is synchronized with the server:

```kotlin
if (timeService.isTimeSynchronized) {
    val precision = timeService.localTimeAdjustmentPrecision
    println("Time is now synchronized with precision ${precision}")
}
```

The precision value represents a maximum absolute deviation of synchronized time against the actual time on the server. For example, a value `500` means that the time provided by the `currentTime` method may be 0.5 seconds ahead or behind the actual time on the server. If the precision is not sufficient for your purpose, for example, if you need to display a real-time countdown in your application, then try to synchronize the time manually. The precision basically depends on how quickly is the synchronization response received and processed from the server. A faster response results in higher precision.

## Common SDK Tasks

### Error Handling

The PowerAuth SDK uses the following types of exceptions:

- `PowerAuthMissingConfigException` - is typically thrown immediately when the `PowerAuthSDK` instance is initialized with an invalid configuration.
- `FailedApiException` - is typically returned to callbacks when an asynchronous HTTP request ends on error.
- `ErrorResponseApiException` - is typically returned to callbacks when an asynchronous HTTP request ends on an error and the error model object is present in the response.
- `PowerAuthErrorException` - typically covers all other erroneous situations. You can investigate a detailed reason for failure by getting the integer, from the set of `PowerAuthErrorCodes` constants.

Here's an example of a typical error-handling procedure:

```kotlin
val t: Throwable // reported in asynchronous callback
when (t) {
    is PowerAuthErrorException -> {
        when (t.powerAuthErrorCode) {
            PowerAuthErrorCodes.NETWORK_ERROR -> Log.d(TAG, "Error code for error with network connectivity or download")
            PowerAuthErrorCodes.SIGNATURE_ERROR -> Log.d(TAG, "Error code for error in signature calculation")
            PowerAuthErrorCodes.INVALID_ACTIVATION_STATE -> Log.d(TAG, "Error code for error that occurs when activation state is invalid")
            PowerAuthErrorCodes.INVALID_ACTIVATION_DATA -> Log.d(TAG, "Error code for error that occurs when activation data is invalid")
            PowerAuthErrorCodes.MISSING_ACTIVATION -> Log.d(TAG, "Error code for error that occurs when activation is required but missing")
            PowerAuthErrorCodes.PENDING_ACTIVATION -> Log.d(TAG, "Error code for error that occurs when pending activation is present and work with completed activation is required")
            PowerAuthErrorCodes.INVALID_ACTIVATION_CODE -> Log.d(TAG, "Error code for error that occurs when invalid activation code is provided.")
            PowerAuthErrorCodes.BIOMETRY_CANCEL -> Log.d(TAG, "Error code for Biometry action cancel error")
            PowerAuthErrorCodes.BIOMETRY_NOT_SUPPORTED -> Log.d(TAG, "The device or operating system doesn't support biometric authentication.")
            PowerAuthErrorCodes.BIOMETRY_NOT_AVAILABLE -> Log.d(TAG, "The biometric authentication is temporarily unavailable.")
            PowerAuthErrorCodes.BIOMETRY_NOT_RECOGNIZED -> Log.d(TAG, "The biometric authentication did not recognize the biometric image") // Reported only during biometric authentication setup
            PowerAuthErrorCodes.BIOMETRY_NOT_ENROLLED -> Log.d(TAG, "The biometric authentication failed because there's no biometry enrolled")
            PowerAuthErrorCodes.BIOMETRY_LOCKOUT -> Log.d(TAG, "The biometric authentication is locked out due to too many failed attempts.")
            PowerAuthErrorCodes.OPERATION_CANCELED -> Log.d(TAG, "Error code for cancelled operations")
            PowerAuthErrorCodes.ENCRYPTION_ERROR -> Log.d(TAG, "Error code for errors related to end-to-end encryption")
            PowerAuthErrorCodes.INVALID_TOKEN -> Log.d(TAG, "Error code for errors related to token-based auth.")
            PowerAuthErrorCodes.PROTOCOL_UPGRADE -> Log.d(TAG, "Error code for error that occurs when protocol upgrade fails at unrecoverable error.")
            PowerAuthErrorCodes.PENDING_PROTOCOL_UPGRADE -> Log.d(TAG, "The operation is temporarily unavailable, due to pending protocol upgrade.")
            PowerAuthErrorCodes.TIME_SYNCHRONIZATION -> Log.d(TAG, "Failed to synchronize time with the server.")
        }
        // Process additional information
        val additionalInfo = error.additionalInformation
        when (additionalInfo) {
            is BiometricErrorInfo -> {
                if (additionalInfo.isErrorPresentationRequired) {
                    //The application should display an error dialog after failed biometric authentication. This is relevant only
                    // if you disabled the biometric error dialog provided by PowerAuth mobile SDK.
                }
            }
        }
    }
    is ErrorResponseApiException -> {
        val errorResponse: Error? = t.errorResponse
        val httpResponseStatusCode = t.responseCode
        // Additional, optional objects assigned to the exception.
        val jsonResponseObject: JsonObject = t.responseJson
        val responseBodyString = t.responseBody
    }
    is FailedApiException -> {
        val httpStatusCode = t.responseCode
        // Additional, optional objects assigned to the exception.
        val jsonResponseObject: JsonObject = t.responseJson
        val responseBodyString = t.responseBody
    }
}
```

Note that you typically don't need to handle all error codes reported in the `PowerAuthErrorException`, or report all those situations to the user. Most of the codes are informational and help the developers properly integrate SDK into the application. A good example is `INVALID_ACTIVATION_STATE`, which typically means that your application's logic is broken and you're using PowerAuthSDK in an unexpected way.

Here's the list of important error codes, which the application should properly handle:

- `BIOMETRY_CANCEL` is reported when the user cancels the biometric authentication dialog
- `PROTOCOL_UPGRADE` is reported when SDK fails to upgrade itself to a newer protocol version. The code may be reported from `PowerAuthSDK.fetchActivationStatusWithCallback()`. This is an unrecoverable error resulting in the broken activation on the device, so the best situation is to inform the user about the situation and remove the activation locally.
- `PENDING_PROTOCOL_UPGRADE` is reported when the requested SDK operation cannot be completed due to a pending PowerAuth protocol upgrade. You can retry the operation later. The code is typically reported in situations when SDK is performing protocol upgrade in the background (as a part of activation status fetch), and the application wants to calculate the PowerAuth authentication code in parallel operation. Such kind of concurrency is forbidden since SDK version `1.0.0`


### Working with Invalid SSL Certificates

Sometimes, you may need to develop or test your application against a service that runs over HTTPS protocol with an invalid (self-signed) SSL certificate. By default, the HTTP client used in PowerAuth SDK communication validates the certificate. To disable the certificate validation, use a `PowerAuthSDK` initializer with a custom client configuration to initialize your PowerAuth SDK instance, like so:

```kotlin
// Set `HttpClientSslNoValidationStrategy as the default client SSL certificate validation strategy
val clientConfiguration = PowerAuthClientConfiguration.Builder()
    .clientValidationStrategy(HttpClientSslNoValidationStrategy())
    .build()
```

Be aware, that using this option will lead to the use of an unsafe implementation of `HostnameVerifier` and `X509TrustManager` SSL client validation. This is useful for debug/testing purposes only, e.g. when an untrusted self-signed SSL certificate is used on the server side.

It's strictly recommended to use this option only in debug flavors of your application. Deploying to production may cause a "Security alert" in the Google Developer Console. Please see [this](https://support.google.com/faqs/answer/7188426) and [this](https://support.google.com/faqs/answer/6346016) Google Help Center articles for more details. Beginning 1 March 2017, Google Play will block the publishing of any new apps or updates that use such unsafe implementation of `HostnameVerifier`.

How to solve this problem for debug/production flavors in the Gradle build script:

1. Define the boolean type `buildConfigField` in the flavor configuration.
   ```gradle
   productFlavors {
      production {
          buildConfigField 'boolean', 'TRUST_ALL_SSL_HOSTS', 'false'
      }
      debug {
          buildConfigField 'boolean', 'TRUST_ALL_SSL_HOSTS', 'true'
      }
   }
   ```

2. In code use this conditional initialization for the `PowerAuthClientConfiguration.Builder` builder.
   ```kotlin
   val clientBuilder = PowerAuthClientConfiguration.Builder()
   if (BuildConfig.TRUST_ALL_SSL_HOSTS) {
       clientBuilder.clientValidationStrategy(HttpClientSslNoValidationStrategy())
   }
   ```

3. Set `minifyEnabled` to true for release buildType to enable code shrinking with ProGuard.


### Debugging

The debug log is by default turned off. To turn it on, use the following code:

```kotlin
PowerAuthLog.setEnabled(true)
```

To turn on an even more detailed log, use the following code:

```kotlin
PowerAuthLog.setVerbose(true)
```

Note that it's highly recommended to turn on this feature only for the `DEBUG` build of your application. For example:

```kotlin
if (BuildConfig.DEBUG) {
    PowerAuthLog.setEnabled(true)
}
```

You can intercept the log and log it into your own report system, you can do so with `PowerAuthLogListener`.

```kotlin
PowerAuthLog.logListener = object : PowerAuthLogListener {
    override fun powerAuthDebugLog(message: String) {
        // Process debug log...
        // Note that the debug log is only reported when 
        // PowerAuthLog.setEnabled(true) is set.
        // We highly discourage using debug logs in production builds.
    }

    override fun powerAuthWarningLog(message: String) {
        // Process warning log...
    }

    override fun powerAuthErrorLog(message: String) {
        // Process error log...
    }
}
```

## Additional Features

PowerAuth SDK for Android contains multiple additional features that are useful for mobile apps.

### Obtaining User's Claims

If supported by the server, the PowerAuth mobile SDK can provide additional information asserted about a person associated with an activation. This information can be obtained either during the activation process or at a later time.

Here is an example of how to process user information during activation:

```kotlin
powerAuthSDK.createActivation(activation, object : ICreateActivationListener {
    override fun onActivationCreateSucceed(result: CreateActivationResult) {
        if (result.userInfo != null) {
            // User information received.
            // At this moment, the object is also available at
            // powerAuthSDK.lastFetchedUserInfo
        }
    }

    override fun onActivationCreateFailed(t: Throwable) {
        // Error handling
    }
})
```

To fetch the user information at a later time, use the following code:

```kotlin
val userInfo = powerAuthSDK.lastFetchedUserInfo
if (userInfo != null) {
    // User information is already available
} else {
    powerAuthSDK.fetchUserInfo(context, object : IUserInfoListener {
        override fun onUserInfoSucceed(userInfo: UserInfo) {
            // User information received
        }

        override fun onUserInfoFailed(t: Throwable) {
            // Error handling
        }
    })
}
```

The obtained `UserInfo` object contains the following properties:

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
| `isEmailVerified`       | `Boolean`| True if the user's email address has been verified, else false<sup>1</sup> |
| `phoneNumber`           | `String` | The user's preferred telephone number<sup>2</sup> |
| `isPhoneNumberVerified` | `Boolean`| True if the user's telephone number has been verified, else false<sup>1</sup> |
| `gender`                | `String` | The user's gender |
| `birthdate`             | `Date`   | The user's birthday |
| `zoneInfo`              | `String` | The user's time zone, e.g. `Europe/Paris` or `America/Los_Angeles` |
| `locale`                | `String` | The end-users locale, represented as a BCP47 language tag<sup>3</sup> |
| `address`               | `UserAddress` | The user's preferred postal address |
| `updatedAt`             | `Date`   | The time the user's information was last updated |
| `allClaims`             | `Map<String, Any>` | The full collection of claims received from the server |

If the `address` is provided, then `UserAddress` contains the following properties:

| Property                | Type     | Description |
|-------------------------|----------|-------------|
| `formatted`             | `String` | The full mailing address, with multiple lines if necessary |
| `street`                | `String` | The street address component, which may include house number, street name, post office box, and other multi-line information |
| `locality`              | `String` | City or locality component |
| `region`                | `String` | State, province, prefecture or region component |
| `postalCode`            | `String` | Zip code or postal code component |
| `country`               | `String` | Country name component |
| `allClaims`             | `Map<String, Any>` | Full collection of claims received from the server |

> Notes:
> 1. Value is false also when a claim is not present in the `allClaims` dictionary
> 2. Phone number is typically in E.164 format, for example `+1 (425) 555-1212` or `+56 (2) 687 2400`
> 3. This is typically an ISO 639-1 Alpha-2 language code in lowercase and an ISO 3166-1 Alpha-2 country code in uppercase, separated by a dash. For example, `en-US` or `fr-CA`

<!-- begin box info -->
Be aware that all properties in the `UserInfo` and `UserAddress` objects are optional and the availability of information depends on actual implementation on the server.
<!-- end -->


### Password Strength Indicator

Choosing a weak passphrase in applications with high-security demands can be potentially dangerous. You can use our [Wultra Passphrase Meter](https://github.com/wultra/passphrase-meter) library to estimate the strength of the passphrase and warn the user when he tries to use such a passphrase in your application.

### Debug Build Detection

It is sometimes useful to switch PowerAuth SDK to a DEBUG build configuration to get more logs from the library. The DEBUG build is usually helpful during application development, but on the other hand, it's highly unwanted in production applications. For this purpose, the `PowerAuthSDK.hasDebugFeatures()` method provides information on whether the PowerAuth JNI library was compiled in the DEBUG configuration. It is a good practice to check this flag and crash the process when the production application is linked against the DEBUG PowerAuth:

```kotlin
if (!BuildConfig.DEBUG) {
    // You can also check your production build configuration
    if (powerAuthSDK.hasDebugFeatures()) {
        throw RuntimeException("Production app with DEBUG PowerAuth")
    }
}
```

### Request Interceptors

The `PowerAuthClientConfiguration` can contain multiple request interceptor objects, allowing you to adjust all HTTP requests created by SDK, before execution. Currently, you can use the following two classes:

- `BasicHttpAuthenticationRequestInterceptor` to add a basic HTTP authentication header to all requests
- `CustomHeaderRequestInterceptor` to add a custom HTTP header to all requests

For example:

```kotlin
val clientConfiguration = PowerAuthClientConfiguration.Builder()
    .requestInterceptor(BasicHttpAuthenticationRequestInterceptor("gateway-user", "gateway-password"))
    .requestInterceptor(CustomHeaderRequestInterceptor("X-CustomHeader", "123456"))
    .build()
```

We don't recommend implementing the `HttpRequestInterceptor` interface on your own. The interface allows you to tweak the requests created in the `PowerAuthSDK` but also gives you an opportunity to break things. So, rather than create your own interceptor, try to contact us and describe what's your problem with the networking in the PowerAuth SDK. Also, keep in mind that the interface may change in the future. We can guarantee the API stability of public classes implementing this interface, but not the stability of the interface itself.

### Custom User-Agent

The `PowerAuthClientConfiguration` contains the `userAgent` property that allows you to set a custom value for the "User-Agent" HTTP request header for all requests initiated by the library:

```kotlin
val clientConfiguration = PowerAuthClientConfiguration.Builder()
    .userAgent("MyApp/1.0.0")
    .build()
```

The default value of the property is composed as "APP-PACKAGE/APP-PACKAGE-VERSION PowerAuth2/PA-VERSION (OS/OS-VERSION, DEVICE-INFO)", for example: "com.test.app/1.0 PowerAuth2/1.7.0 (Android 11.0.0, SM-A525F)".

If you set `""` (empty string) to the `userAgent` property, then the default "User-Agent" provided by the operating system will be used. 
