# PowerAuth Mobile SDK for Android

<!-- begin remove -->
## Table of Contents

- [SDK Installation](#installation)
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
- [Biometric Authentication Setup](#biometric-authentication-setup)
- [Device Activation Removal](#activation-removal)
- [End-To-End Encryption](#end-to-end-encryption)
- [Secure Vault](#secure-vault)
- [Recovery Codes](#recovery-codes)
   - [Getting Recovery Data](#getting-recovery-data)
   - [Confirm Recovery Postcard](#confirm-recovery-postcard)
- [Token-Based Authentication](#token-based-authentication)
- [External Encryption Key](#external-encryption-key)
- [Synchronized Time](#synchronized-time)
- [Common SDK Tasks](#common-sdk-tasks)
- [Additional Features](#additional-features)
  - [Personal Information About User](#personal-information-about-user)
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

<!-- begin codetabs Kotlin Java -->
```kotlin
val INSTANCE_ID = applicationContext.packageName
val MOBILE_SDK_CONFIG = "MTIzNDU2Nz...jc4OTAxMg=="
val API_SERVER = "https://localhost:8080/demo-server"

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
```java
String INSTANCE_ID = getApplicationContext().getPackageName();
String MOBILE_SDK_CONFIG = "MTIzNDU2Nz...jc4OTAxMg==";
String API_SERVER = "https://localhost:8080/demo-server";

try {
    final PowerAuthConfiguration configuration = new PowerAuthConfiguration.Builder(
            INSTANCE_ID,
            MOBILE_SDK_CONFIG)
            .build();

    PowerAuthSDK powerAuthSDK = new PowerAuthSDK.Builder(configuration)
            .build(getApplicationContext());

} catch (PowerAuthErrorException e) {
    // Failed to construct `PowerAuthSDK` due to insufficient keychain protection.
    // (See next chapter for details)
}
```
<!-- end -->


If you don't provide application's context to `build()` method, then PowerAuthSDK will fail to register its components for application's lifecycle callbacks. To fix this, please use the following code in your application's `onCreate()` method:

```kotlin
PowerAuthAppLifecycleListener.getInstance().registerForActivityLifecycleCallbacks(this) // "this" is Application
```


### Additional configuration methods

The `PowerAuthConfiguration.Builder` class provides the following additional methods that can alter the configuration:

- `offlineSignatureComponentLength()` - Alters the default component length for the [offline signature](#symmetric-offline-multi-factor-signature). The values between 4 and 8 are allowed. The default value is 8.
- `externalEncryptionKey()` - See [External Encryption Key](#external-encryption-key) chapter for more details.
- `disableAutomaticProtocolUpgrade()` - Disables the automatic protocol upgrade. This option should be used only for the debugging purposes.

### Activation Data Protection

By default, the PowerAuth Mobile SDK for Android encrypts the local activation data with a symmetric key generated by the Android KeyStore on the Android 6 and newer devices. On older devices, or if the device has an unreliable KeyStore implementation, then the fallback to unencrypted storage, based on private [SharedPreferences](https://developer.android.com/reference/android/content/SharedPreferences) is used. If your application requires a higher level of activation data protection, then you can enforce the level of protection in `PowerAuthKeychainConfiguration`:

<!-- begin codetabs Kotlin Java -->
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
```java
try {
    PowerAuthKeychainConfiguration keychainConfig = new PowerAuthKeychainConfiguration.Builder()
            .minimalRequiredKeychainProtection(KeychainProtection.HARDWARE)
            .build();
    // Apply keychain configuration
    PowerAuthSDK powerAuthSDK = new PowerAuthSDK.Builder(configuration)
            .keychainConfiguration(keychainConfig)
            .build(getApplicationContext());

} catch (PowerAuthErrorException e) {
    // Failed to construct `PowerAuthSDK` due to insufficient keychain protection.
}
```
<!-- end -->

You can also determine the level of keychain protection before `PowerAuthSDK` object creation by calling:

<!-- begin codetabs Kotlin Java -->
```kotlin
val keychainProtectionLevel = KeychainFactory.getKeychainProtectionSupportedOnDevice(context)
```
```java
@KeychainProtection int keychainProtectionLevel = KeychainFactory.getKeychainProtectionSupportedOnDevice(context));
```
<!-- end -->

The following levels of keychain protection are defined:

- `NONE` - The content of the keychain is not encrypted and therefore not protected. This level of the protection is typically reported on devices older than Android Marshmallow, or in case that the device has faulty KeyStore implementation.

- `SOFTWARE` - The content of the keychain is encrypted with key generated by Android KeyStore, but the key is protected only on the operating system level. The security of the key material relies solely on software measures, which means that a compromise of the Android OS (such as root exploit) might up revealing this key.

- `HARDWARE` - The content of the keychain is encrypted with key generated by Android KeyStore and the key is stored and managed by [Trusted Execution Environment](https://en.wikipedia.org/wiki/Trusted_execution_environment).

- `STRONGBOX` - The content of the keychain is encrypted with key generated by Android KeyStore and the key is stored inside of Secure Element (e.g. StrongBox). This is the highest level of Keychain protection currently available, but not enabled by default. See [note below](#strongbox-support-note).

Be aware, that enforcing the required level of protection must be properly reflected in your application's user interface. That means that you should inform the user in case that the device has an insufficient capabilities to run your application securely.

#### StrongBox Support Note

The StrongBox backed keys are by default turned-off due to poor reliability and low performance of StrongBox implementations on the current Android devices. If you want to turn support on in your application, then use the following code at your application's startup:

<!-- begin codetabs Kotlin Java -->
```kotlin
try {
    KeychainFactory.setStrongBoxEnabled(context, true)
} catch (e: PowerAuthErrorException) {
    // You must alter the configuration before any keychain is accessed.
    // Basically, you should not create any PowerAuthSDK instance before the change.
}
```
```java
try {
    KeychainFactory.setStrongBoxEnabled(context, true);
} catch (PowerAuthErrorException e) {
    // You must alter the configuration before any keychain is accessed.
    // Basically, you should not create any PowerAuthSDK instance before the change.
}
```
<!-- end -->

## Activation

After you configure the SDK instance, you are ready to make your first activation.

### Activation via Activation Code

The original activation method uses a one-time activation code generated in PowerAuth Server. To create an activation using this method, some external application (Internet banking, ATM application, branch / kiosk application) must generate an activation code for you and display it (as a text or in a QR code).

In case you would like to use QR code scanning to enter an activation code, you can use any library of your choice, for example [Barcode Scanner](https://github.com/dm77/barcodescanner) open-source library based on ZBar lib.

Use the following code to create an activation once you have an activation code:

<!-- begin codetabs Kotlin Java -->
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

// Create a new activation with given activation object
powerAuthSDK.createActivation(activation, object: ICreateActivationListener {
    override fun onActivationCreateSucceed(result: CreateActivationResult) {
        val fingerprint = result.activationFingerprint
        val activationRecovery = result.recoveryData
        // No error occurred, proceed to credentials entry (PIN prompt, Enable "Fingerprint Authentication" switch, ...) and commit
        // The 'fingerprint' value represents the combination of device and server public keys - it may be used as visual confirmation
        // If server supports recovery codes for activation, then `activationRecovery` contains object with information about activation recovery.
    }

    override fun onActivationCreateFailed(t: Throwable) {
        // Error occurred, report it to the user
    }
})
```
```java
String deviceName = "Petr's Leagoo T5C";
String activationCode = "VVVVV-VVVVV-VVVVV-VTFVA"; // let user type or QR-scan this value

// Create activation object with given activation code.
final PowerAuthActivation activation;
try {
    activation = PowerAuthActivation.Builder.activation(activationCode, deviceName).build();
} catch (PowerAuthErrorException e) {
    // Invalid activation code
}

// Create a new activation with given activation object
powerAuthSDK.createActivation(activation, new ICreateActivationListener() {
    @Override
    public void onActivationCreateSucceed(CreateActivationResult result) {
        final String fingerprint = result.getActivationFingerprint();
        final RecoveryData activationRecovery = result.getRecoveryData();
        // No error occurred, proceed to credentials entry (PIN prompt, Enable "Fingerprint Authentication" switch, ...) and commit
        // The 'fingerprint' value represents the combination of device and server public keys - it may be used as visual confirmation
        // If server supports recovery codes for activation, then `activationRecovery` contains object with information about activation recovery.
    }

    @Override
    public void onActivationCreateFailed(Throwable t) {
        // Error occurred, report it to the user
    }
});
```
<!-- end -->

If the received activation result also contains recovery data, then you should display that values to the user. To do that, please read the [Getting Recovery Data](#getting-recovery-data) section of this document, which describes how to treat that sensitive information. This is relevant for all types of activation you use.

#### Additional Activation OTP

If an [additional activation OTP](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Additional-Activation-OTP.md) is required to complete the activation, then use the following code to configure the `PowerAuthActivation` object:

<!-- begin codetabs Kotlin Java -->
```kotlin
val deviceName = "Petr's iPhone 7" // or UIDevice.current.name
val activationCode = "VVVVV-VVVVV-VVVVV-VTFVA" // let user type or QR-scan this value
val activationOtp = "12345"

// Create activation object with given activation code and OTP.
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
```java
String deviceName = "Petr's iPhone 7" // or UIDevice.current.name
String activationCode = "VVVVV-VVVVV-VVVVV-VTFVA" // let user type or QR-scan this value
String activationOtp = "12345"

// Create activation object with given activation code and OTP.
final PowerAuthActivation activation;
try {
    activation = PowerAuthActivation.Builder.activation(activationCode, deviceName)
        .setAdditionalActivationOtp(activationOtp)
        .build();
} catch (PowerAuthErrorException e) {
    // Invalid activation code
}
// The rest of the activation routine is the same.
```
<!-- end -->

<!-- begin box warning -->
Be aware that OTP can be used only if the activation is configured for ON_KEY_EXCHANGE validation on the PowerAuth server. See our [crypto documentation for details](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Additional-Activation-OTP.md#regular-activation-with-otp).
<!-- end -->

### Activation via Custom Credentials

You may also create an activation using any custom login data - it can be anything that the server can use to obtain the user ID to associate with a new activation. Since the credentials are custom, the server's implementation must be able to process such a request. Unlike the previous versions of SDK, the custom activation no longer requires a custom activation endpoint.

Use the following code to create an activation using custom credentials:

<!-- begin codetabs Kotlin Java -->
```kotlin
// Create a new activation with a given device name and login credentials
val deviceName = "Juraj's JiaYu S3"
val credentials = mapOf("username" to "john.doe@example.com", "password" to "YBzBEM")

// Create activation object with given credentials.
val activation: PowerAuthActivation
try {
    activation = PowerAuthActivation.Builder.customActivation(credentials, deviceName).build()
} catch (e: PowerAuthErrorException) {
    // Credentials dictionary is empty
}

// Create a new activation with given activation object
powerAuthSDK.createActivation(activation, object: ICreateActivationListener {
    override fun onActivationCreateSucceed(result: CreateActivationResult) {
        val fingerprint = result.activationFingerprint
        val activationRecovery = result.recoveryData
        // No error occurred, proceed to credentials entry (PIN prompt, Enable "Biometric Authentication" switch, ...) and commit
        // The 'fingerprint' value represents the combination of device and server public keys - it may be used as visual confirmation
        // If server supports recovery codes for activation, then `activationRecovery` contains object with information about activation recovery.
    }

    override fun onActivationCreateFailed(t: Throwable) {
        // Error occurred, report it to the user
    }
})
```
```java
// Create a new activation with a given device name and login credentials
String deviceName = "Juraj's JiaYu S3";
Map<String, String> credentials = new HashMap<>();
credentials.put("username", "john.doe@example.com");
credentials.put("password", "YBzBEM");

// Create activation object with given credentials.
final PowerAuthActivation activation;
try {
    activation = PowerAuthActivation.Builder.customActivation(credentials, deviceName).build();
} catch (PowerAuthErrorException e) {
    // Credentials dictionary is empty
}

// Create a new activation with given activation object
powerAuthSDK.createActivation(activation, new ICreateActivationListener() {
    @Override
    public void onActivationCreateSucceed(CreateActivationResult result) {
        final String fingerprint = result.getActivationFingerprint();
        final RecoveryData activationRecovery = result.getRecoveryData();
        // No error occurred, proceed to credentials entry (PIN prompt, Enable "Biometric Authentication" switch, ...) and commit
        // The 'fingerprint' value represents the combination of device and server public keys - it may be used as visual confirmation
        // If server supports recovery codes for activation, then `activationRecovery` contains object with information about activation recovery.
    }

    @Override
    public void onActivationCreateFailed(Throwable t) {
        // Error occurred, report it to the user
    }
});
```
<!-- end -->

Note that by using weak identity attributes to create an activation, the resulting activation is confirming a "blurry identity". This may greatly limit the legal weight and usability of a signature. We recommend using a strong identity verification before activation can actually be created.


### Activation via Recovery Code

If PowerAuth Server is configured to support [Recovery Codes](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Activation-Recovery.md), then also you can create an activation via the recovery code and PUK.

Use the following code to create an activation using recovery code:

<!-- begin codetabs Kotlin Java -->
```kotlin
val deviceName = "John Tramonta"
val recoveryCode = "55555-55555-55555-55YMA" // User's input
val puk = "0123456789" // User's input. You should validate RC & PUK with using ActivationCodeUtil

// Create activation object with given recovery code and PUK.
val activation: PowerAuthActivation
try {
    activation = PowerAuthActivation.Builder.recoveryActivation(recoveryCode, puk, deviceName).build();
} catch (e: PowerAuthErrorException) {
    // Invalid recovery code or PUK
}

// Create a new activation with given activation object
powerAuthSDK.createActivation(activation, object: ICreateActivationListener {
    override fun onActivationCreateSucceed(result: CreateActivationResult) {
        val fingerprint = result.activationFingerprint
        val activationRecovery = result.recoveryData
        // No error occurred, proceed to credentials entry (PIN prompt, Enable "Biometric Authentication" switch, ...) and commit
        // The 'fingerprint' value represents the combination of device and server public keys - it may be used as visual confirmation
        // If server supports recovery codes for activation, then `activationRecovery` contains object with information about activation recovery.
    }

    override fun onActivationCreateFailed(t: Throwable) {
        // Error occurred, report it to the user
        // On top of a regular error processing, you should handle a special situation, when server gives an additional information
        // about which PUK must be used for the recovery. The information is valid only when recovery code from a postcard is applied.
        if (t is ErrorResponseApiException) {
            val errorResponse = t.errorResponse
            val currentRecoveryPukIndex = t.currentRecoveryPukIndex
            if (currentRecoveryPukIndex > 0) {
                // The PUK index is known, you should inform user that it has to rewrite PUK from a specific position.
            }
        }
    }
})
```
```java
final String deviceName = "John Tramonta"
final String recoveryCode = "55555-55555-55555-55YMA" // User's input
final String puk = "0123456789" // User's input. You should validate RC & PUK with using ActivationCodeUtil

// Create activation object with given recovery code and PUK.
final PowerAuthActivation activation;
try {
    activation = PowerAuthActivation.Builder.recoveryActivation(recoveryCode, puk, deviceName).build();
} catch (PowerAuthErrorException e) {
    // Invalid recovery code or PUK
}

// Create a new activation with given activation object
powerAuthSDK.createActivation(activation, new ICreateActivationListener() {
    @Override
    public void onActivationCreateSucceed(CreateActivationResult result) {
        final String fingerprint = result.getActivationFingerprint();
        final RecoveryData activationRecovery = result.getRecoveryData();
        // No error occurred, proceed to credentials entry (PIN prompt, Enable "Biometric Authentication" switch, ...) and commit
        // The 'fingerprint' value represents the combination of device and server public keys - it may be used as visual confirmation
        // If server supports recovery codes for activation, then `activationRecovery` contains object with information about activation recovery.
    }

    @Override
    public void onActivationCreateFailed(Throwable t) {
        // Error occurred, report it to the user
        // On top of a regular error processing, you should handle a special situation, when server gives an additional information
        // about which PUK must be used for the recovery. The information is valid only when recovery code from a postcard is applied.
        if (t instanceof ErrorResponseApiException) {
            ErrorResponseApiException exception = (ErrorResponseApiException) t;
            Error errorResponse = exception.getErrorResponse();
            int currentRecoveryPukIndex = exception.getCurrentRecoveryPukIndex();
            if (currentRecoveryPukIndex > 0) {
                // The PUK index is known, you should inform user that it has to rewrite PUK from a specific position.
            }
        }
    }
});
```
<!-- end -->

### Customize Activation

You can set an additional properties to `PowerAuthActivation` object, before any type of activation is created. For example:

<!-- begin codetabs Kotlin Java -->
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
```java
String deviceName = "Petr's Leagoo T5C";
String activationCode = "VVVVV-VVVVV-VVVVV-VTFVA"; // let user type or QR-scan this value

// Custom attributes that can be processed before the activation is created on PowerAuth Server.
// The dictionary may contain only values that can be serialized to JSON.
List<String> otherIds = new ArrayList<>();
otherIds.add("e43f5f99-e2e9-49f2-bcae-5e32a5e96d22");
otherIds.add("41dd704c-65e6-4d4b-b28f-0bc0e4eb9715");

Map<String, Object> customAttributes = new HashMap<>();
customAttributes.put("isPrimaryActivation", true);
customAttributes.put("otherActivationIds", otherIds);

// Extra flags that will be associated with the activation record on PowerAuth Server.
String extraFlags = "EXTRA_FLAGS"

// Now create the activation object with all that extra data
final PowerAuthActivation activation;
try {
    activation = PowerAuthActivation.Builder.activation(activationCode, deviceName)
            .setCustomAttributes(customAttributes)
            .setExtras(extraFlags)
            .build();
} catch (PowerAuthErrorException e) {
    // Invalid activation code
}
// The rest of the activation routine is the same.
```  
<!-- end -->

### Committing Activation Data

After you create an activation using one of the methods mentioned above, you need to commit the activation - to use provided user credentials to store the activation data on the device. Use the following code to do this.

<!-- begin codetabs Kotlin Java -->
```kotlin
// Commit activation using given PIN
val result = powerAuthSDK.commitActivationWithPassword(context, pin)
if (result != PowerAuthErrorCodes.SUCCEED) {
    // happens only in case SDK was not configured or activation is not in state to be committed
}
```
```java
// Commit activation using given PIN
int result = powerAuthSDK.commitActivationWithPassword(context, pin);
if (result != PowerAuthErrorCodes.SUCCEED) {
    // happens only in case SDK was not configured or activation is not in state to be committed
}
```
<!-- end -->

This code has created activation with two factors: possession (key stored using a key derived from a device fingerprint) and knowledge (password, in our case, a simple PIN code). If you would like to enable biometric authentication support at this moment, use the following code instead of the one above:

<!-- begin codetabs Kotlin Java -->
```kotlin
// Commit activation using given PIN and ad-hoc generated biometric related key
powerAuthSDK.commitActivation(context, fragment, "Enable Biometric Authentication", "To enable biometric authentication, use the biometric sensor on your device.", pin, object: ICommitActivationWithBiometryListener {
    override fun onBiometricDialogCancelled() {
        // Biometric enrolment cancelled by user
    }

    override fun onBiometricDialogSuccess() {
        // success, activation has been committed
    }

    override fun onBiometricDialogFailed(error: PowerAuthErrorException) {
        // failure, typically as a result of API misuse, or a biometric authentication failure
    }
})
```
```java
// Commit activation using given PIN and ad-hoc generated biometric related key
powerAuthSDK.commitActivation(context, fragment, "Enable Biometric Authentication", "To enable biometric authentication, use the biometric sensor on your device.", pin, new ICommitActivationWithBiometryListener() {
    @Override
    public void onBiometricDialogCancelled() {
        // Biometric enrolment cancelled by user
    }

    @Override
    public void onBiometricDialogSuccess() {
        // success, activation has been committed
    }

    @Override
    public void onBiometricDialogFailed(@NonNull PowerAuthErrorException error) {
        // failure, typically as a result of API misuse, or a biometric authentication failure
    }
});
```
<!-- end -->

Also, you can use the following code to create activation with the best granularity control:

<!-- begin codetabs Kotlin Java -->
```kotlin
val authentication = PowerAuthAuthentication.commitWithPasswordAndBiometry(pin, biometryFactorRelatedKey)
val result = powerAuthSDK.commitActivationWithAuthentication(context, authentication)
if (result != PowerAuthErrorCodes.SUCCEED) {
    // happens only in case SDK was not configured or activation is not in state to be committed
}
```
```java
PowerAuthAuthentication authentication = PowerAuthAuthentication.commitWithPasswordAndBiometry(pin, biometryFactorRelatedKey);
int result =  powerAuthSDK.commitActivationWithAuthentication(context, authentication);
if (result != PowerAuthErrorCodes.SUCCEED) {
    // happens only in case SDK was not configured or activation is not in state to be committed
}
```
<!-- end -->

Note that you currently need to obtain the biometry factor-related key yourself - you have to use `BiometricPrompt.CryptoObject` or integration with Android `KeyStore` to do so.

### Validating User Inputs

The mobile SDK is providing a couple of functions in `ActivationCodeUtil` class, helping with user input validation. You can:

- Parse activation code when it's scanned from QR code
- Validate a whole code at once
- Validate recovery code or PUK
- Auto-correct characters typed on the fly

#### Validating Scanned QR Code

To validate an activation code scanned from QR code, you can use `ActivationCodeUtil.parseFromActivationCode()` function. You have to provide the code with or without the signature part. For example:

<!-- begin codetabs Kotlin Java -->
```kotlin
val scannedCode = "VVVVV-VVVVV-VVVVV-VTFVA#aGVsbG8.....gd29ybGQ="
val code = ActivationCodeUtil.parseFromActivationCode(scannedCode);
if (code?.activationCode == null) {
    // Invalid code, QR code should contain a signature
    return;
}
```
```java
final String scannedCode = "VVVVV-VVVVV-VVVVV-VTFVA#aGVsbG8.....gd29ybGQ=";
final ActivationCode code = ActivationCodeUtil.parseFromActivationCode(scannedCode);
if (code == null || code.activationCode == null) {
    // Invalid code, QR code should contain a signature
    return;
}
```
<!-- end -->

Note that the signature is only formally validated in the function above. The actual signature verification is done in the activation process, or you can do it on your own:

<!-- begin codetabs Kotlin Java -->
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
```java
final String scannedCode = "VVVVV-VVVVV-VVVVV-VTFVA#aGVsbG8......gd29ybGQ=";
final ActivationCode code = ActivationCodeUtil.parseFromActivationCode(scannedCode);
if (code == null || code.activationCode == null) {
    return;
}
final byte[] codeBytes = code.activationCode.getBytes(Charset.defaultCharset());
final byte[] signatureBytes = Base64.decode(code.activationSignature, Base64.NO_WRAP);
if (!powerAuthSDK.verifyServerSignedData(codeBytes, signatureBytes, true)) {
    // Invalid signature
}
```
<!-- end -->

#### Validating Entered Activation Code

To validate an activation code at once, you can call `ActivationCodeUtil.validateActivationCode()` function. You have to provide the code without the signature part. For example:

<!-- begin codetabs Kotlin Java -->
```kotlin
val isValid = ActivationCodeUtil.validateActivationCode("VVVVV-VVVVV-VVVVV-VTFVA")
val isInvalid = ActivationCodeUtil.validateActivationCode("VVVVV-VVVVV-VVVVV-VTFVA#aGVsbG8gd29ybGQ=")
```
```java
boolean isValid   = ActivationCodeUtil.validateActivationCode("VVVVV-VVVVV-VVVVV-VTFVA");
boolean isInvalid = ActivationCodeUtil.validateActivationCode("VVVVV-VVVVV-VVVVV-VTFVA#aGVsbG8gd29ybGQ=");
```
<!-- end -->

If your application is using your own validation, then you should switch to functions provided by SDK. The reason for that is that since SDK `1.0.0`, all activation codes contain a checksum, so it's possible to detect mistyped characters before you start the activation. Check our [Activation Code](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Activation-Code.md) documentation for more details.

#### Validating Recovery Code and PUK

To validate a recovery code at once, you can call `ActivationCodeUtil.validateRecoveryCode()` function. You can provide the whole code, which may or may not contain `"R:"` prefix. So, you can validate manually entered codes, but also codes scanned from QR. For example:

<!-- begin codetabs Kotlin Java -->
```kotlin
val isValid1 = ActivationCodeUtil.validateRecoveryCode("VVVVV-VVVVV-VVVVV-VTFVA")
val isValid2 = ActivationCodeUtil.validateRecoveryCode("R:VVVVV-VVVVV-VVVVV-VTFVA")
```
```java
boolean isValid1 = ActivationCodeUtil.validateRecoveryCode("VVVVV-VVVVV-VVVVV-VTFVA");
boolean isValid2 = ActivationCodeUtil.validateRecoveryCode("R:VVVVV-VVVVV-VVVVV-VTFVA");
```
<!-- end -->

To validate PUK at once, you can call `ActivationCodeUtil.validateRecoveryPuk()` function:

<!-- begin codetabs Kotlin Java -->
```kotlin
val isValid = ActivationCodeUtil.validateRecoveryPuk("0123456789")
```
```java
boolean isValid   = ActivationCodeUtil.validateRecoveryPuk("0123456789");
```
<!-- end -->

#### Auto-Correcting Typed Characters

You can implement auto-correcting of typed characters with using `ActivationCodeUtil.validateAndCorrectTypedCharacter()` function in screens, where user is supposed to enter an activation or recovery code. This technique is possible due to the fact that Base32 is constructed so that it doesn't contain visually confusing characters. For example, `1` (number one) and `I` (capital I) are confusing, so only `I` is allowed. The benefit is that the provided function can correct typed `1` and translate it to `I`.

Here's an example how to iterate over the string and validate it character by character:

<!-- begin codetabs Kotlin Java -->
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
```java
/// Returns corrected character or null in case of error.
@Nullable String validateTypedCharacters(@NonNull String input) {
    final int length = input.length();
    final StringBuilder output = new StringBuilder(length);
    for (int offset = 0; offset < length; ) {
        final int codepoint = input.codePointAt(offset);
        offset += Character.charCount(codepoint);
        final int corrected = ActivationCodeUtil.validateAndCorrectTypedCharacter(codepoint);
        if (corrected == 0) {
            return null;
        }
        // Character.isBmpCodePoint(corrected) is always true
        output.append((char)corrected);
    }
    return output.toString();
}

// validateTypedCharacter("v1") == "VI"
// validateTypedCharacter("9") == null
```
<!-- end -->

## Requesting Activation Status

To obtain a detailed activation status information, use the following code:

<!-- begin codetabs Kotlin Java -->
```kotlin
// Check if there is some activation on the device
if (powerAuthSDK.hasValidActivation()) {
    // If there is an activation on the device, check the status with server
    powerAuthSDK.fetchActivationStatusWithCallback(context, object: IActivationStatusListener {
        override fun onActivationStatusSucceed(status: ActivationStatus) {
            // Activation state: State_Created, State_Pending_Commit, State_Active, State_Blocked, State_Removed, State_Deadlock
            when (status.state) {
                ActivationStatus.State_Pending_Commit ->
                    // Activation is awaiting commit on the server.
                    Log.i(TAG, "Waiting for commit")
                ActivationStatus.State_Active ->
                    // Activation is valid and active.
                    Log.i(TAG, "Activation is active")
                ActivationStatus.State_Blocked ->
                    // Activation is blocked. You can display unblock
                    // instructions to the user.
                    Log.i(TAG, "Activation is blocked")
                ActivationStatus.State_Removed -> {
                    // Activation is no longer valid on the server.
                    // You can inform user about this situation and remove
                    // activation locally.
                    Log.i(TAG, "Activation is no longer valid")
                    powerAuthSDK.removeActivationLocal(context)
                }
                ActivationStatus.State_Deadlock -> {
                    // Local activation is technically blocked and no longer
                    // can be used for the signature calculations. You can inform
                    // user about this situation and remove activation locally.
                    Log.i(TAG, "Activation is technically blocked")
                    powerAuthSDK.removeActivationLocal(context)
                }
                ActivationStatus.State_Created -> Log.i(TAG, "Unknown state")
                else -> Log.i(TAG, "Unknown state")
            }

            // Failed login attempts, remaining = max - current
            val currentFailCount: Int = status.failCount
            val maxAllowedFailCount: Int = status.maxFailCount
            val remainingFailCount: Int = status.remainingAttempts
            if (status.customObject != null) {
                // Custom object contains any proprietary server specific data
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
```java
// Check if there is some activation on the device
if (powerAuthSDK.hasValidActivation()) {
    // If there is an activation on the device, check the status with server
    powerAuthSDK.fetchActivationStatusWithCallback(context, new IActivationStatusListener() {
        @Override
        public void onActivationStatusSucceed(ActivationStatus status) {
            // Activation state: State_Created, State_Pending_Commit, State_Active, State_Blocked, State_Removed, State_Deadlock
            switch (status.state) {
                case ActivationStatus.State_Pending_Commit:
                    // Activation is awaiting commit on the server.
                    android.util.Log.i(TAG, "Waiting for commit");
                    break;
                case ActivationStatus.State_Active:
                    // Activation is valid and active.
                    android.util.Log.i(TAG, "Activation is active");
                    break;
                case ActivationStatus.State_Blocked:
                    // Activation is blocked. You can display unblock
                    // instructions to the user.
                    android.util.Log.i(TAG, "Activation is blocked");
                    break;
                case ActivationStatus.State_Removed:
                    // Activation is no longer valid on the server.
                    // You can inform user about this situation and remove
                    // activation locally.
                    android.util.Log.i(TAG, "Activation is no longer valid");
                    powerAuthSDK.removeActivationLocal(context);
                    break;
                case ActivationStatus.State_Deadlock:
                    // Local activation is technically blocked and no longer
                    // can be used for the signature calculations. You can inform
                    // user about this situation and remove activation locally.
                    android.util.Log.i(TAG, "Activation is technically blocked");
                    powerAuthSDK.removeActivationLocal(context);
                    break;
                case ActivationStatus.State_Created:
                    // Activation is just created. This is the internal
                    // state on the server and therefore can be ignored
                    // on the mobile application.
                default:
                    android.util.Log.i(TAG, "Unknown state");
                    break;
            }

            // Failed login attempts, remaining = max - current
            int currentFailCount = status.failCount;
            int maxAllowedFailCount = status.maxFailCount;
            int remainingFailCount = status.getRemainingAttempts();

            if (status.getCustomObject() != null) {
                // Custom object contains any proprietary server specific data
            }
        }

        @Override
        public void onActivationStatusFailed(Throwable t) {
            // Network error occurred, report it to the user
        }
    });
} else {
    // No activation present on device
}
```
<!-- end -->

Note that the status fetch may fail at an unrecoverable error `PowerAuthErrorCodes.PROTOCOL_UPGRADE`, meaning that it's not possible to upgrade the PowerAuth protocol to a newer version. In this case, it's recommended to [remove the activation locally](#activation-removal).

To get more information about activation lifecycle, check the [Activation States](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Activation.md#activation-states) chapter available in our [powerauth-crypto](https://github.com/wultra/powerauth-crypto) repository.

## Data Signing

The main feature of the PowerAuth protocol is data signing. PowerAuth has two types of signatures:

- **Symmetric Multi-Factor Signature**: Suitable for most operations, such as login, new payment or confirming changes in settings.
- **Asymmetric Private Key Signature**: Suitable for documents where a strong one-sided signature is desired.
- **Symmetric Offline Multi-Factor Signature**: Suitable for very secure operations, where the signature is validated over the out-of-band channel.
- **Verify server signed data**: Suitable for receiving arbitrary data from the server.

### Symmetric Multi-Factor Signature

To sign request data, you need to first obtain user credentials (password, PIN code, biometric image) from the user. The task of obtaining the user credentials is used in more use-cases covered by the SDK. The core class is `PowerAuthAuthentication` that holds information about the used authentication factors:

<!-- begin codetabs Kotlin Java -->
```kotlin
// 1FA signature, uses device related key only.
val oneFactor = PowerAuthAuthentication.possession()

// 2FA signature, uses device related key and user PIN code.
val twoFactorPassword = PowerAuthAuthentication.possessionWithPassword("1234")

// 2FA signature, uses biometry factor-related key as a 2nd. factor.
// To obtain biometryFactorRelatedKey see "Fetching the Biometry Factor-Related Key for Authentication" chapter.
val twoFactorBiometry = PowerAuthAuthentication.possessionWithBiometry(biometryFactorRelatedKey)
```
```java
// 1FA signature, uses device related key only.
PowerAuthAuthentication oneFactor = PowerAuthAuthentication.possession();

// 2FA signature, uses device related key and user PIN code.
PowerAuthAuthentication twoFactorPassword = PowerAuthAuthentication.possessionWithPassword("1234");

// 2FA signature, uses biometry factor-related key as a 2nd. factor.
// To obtain biometryFactorRelatedKey see "Fetching the Biometry Factor-Related Key for Authentication" chapter.
PowerAuthAuthentication twoFactorBiometry = PowerAuthAuthentication.possessionWithBiometry(biometryFactorRelatedKey);
```
<!-- end -->

When signing `POST`, `PUT` or `DELETE` requests, use request body bytes (UTF-8) as request data and the following code:

<!-- begin codetabs Kotlin Java -->
```kotlin
// 2FA signature, uses device related key and user PIN code
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")

// Sign POST call with provided data made to URI with custom identifier "/payment/create"
val header = powerAuthSDK.requestSignatureWithAuthentication(context, authentication, "POST", "/payment/create", requestBodyBytes)
if (header.isValid) {
    val httpHeaderKey = header.getKey()
    val httpHeaderValue = header.getValue()
} else {
    // In case of invalid configuration, invalid activation state or corrupted state data
}
```
```java
// 2FA signature, uses device related key and user PIN code
PowerAuthAuthentication authentication = PowerAuthAuthentication.possessionWithPassword("1234");

// Sign POST call with provided data made to URI with custom identifier "/payment/create"
PowerAuthAuthorizationHttpHeader header = powerAuthSDK.requestSignatureWithAuthentication(context, authentication, "POST", "/payment/create", requestBodyBytes);
if (header.isValid()) {
    String httpHeaderKey = header.getKey();
    String httpHeaderValue = header.getValue();
} else {
    // In case of invalid configuration, invalid activation state or corrupted state data
}
```
<!-- end -->

When signing `GET` requests, use the same code as above with normalized request data as described in specification, or (preferably) use the following helper method:

<!-- begin codetabs Kotlin Java -->
```kotlin
// 2FA signature, uses device related key and user PIN code
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")

// Sign GET call with provided query parameters made to URI with custom identifier "/payment/create"
val params = mapOf("param1" to "value1", "param2" to "value2")

val header = powerAuthSDK.requestGetSignatureWithAuthentication(context, authentication, "/payment/create", params)
if (header.isValid) {
    val httpHeaderKey = header.getKey()
    val httpHeaderValue = header.getValue()
} else {
    // In case of invalid configuration, invalid activation state or corrupted state data
}
```
```java
// 2FA signature, uses device related key and user PIN code
PowerAuthAuthentication authentication = PowerAuthAuthentication.possessionWithPassword("1234");

// Sign GET call with provided query parameters made to URI with custom identifier "/payment/create"
Map<String, String> params = new HashMap<>();
params.put("param1", "value1");
params.put("param2", "value2");

PowerAuthAuthorizationHttpHeader header = powerAuthSDK.requestGetSignatureWithAuthentication(context, authentication, "/payment/create", params);
if (header.isValid()) {
    String httpHeaderKey = header.getKey();
    String httpHeaderValue = header.getValue();
} else {
    // In case of invalid configuration, invalid activation state or corrupted state data
}
```
<!-- end -->

The result of the signature is appropriate HTTP header - you are responsible for hooking up the header value in your request correctly. The process with libraries like `OkHttp` goes like this:

<!-- begin codetabs Kotlin Java -->
```kotlin
// Prepare the request builder
val builder: Request.Builder = Builder().url(endpoint)

// Compute PA signature header
val header = powerAuthSDK.requestSignatureWithAuthentication(context, signatureUnlockKeys, "POST", "/session/login", jsonBody)
if (!header.isValid) {
    // request signature failed, for example due to incorrect activation status - cancel the process
    return
}

// Add HTTP header in the request builder
builder.header(header.getKey(), header.getValue())

// Build the request, send it and process response...
// ...
```
```java
// Prepare the request builder
final Request.Builder builder = new Request.Builder().url(endpoint);

// Compute PA signature header
PowerAuthAuthorizationHttpHeader header = powerAuthSDK.requestSignatureWithAuthentication(context, signatureUnlockKeys, "POST", "/session/login", jsonBody);
if (!header.isValid()) {
    // request signature failed, for example due to incorrect activation status - cancel the process
    return;
 }

// Add HTTP header in the request builder
builder.header(header.getKey(), header.getValue());

// Build the request, send it and process response...
// ...
```
<!-- end -->

#### Request Synchronization

It is recommended that your application executes only one signed request at the time. The reason for that is that our signature scheme is using a counter as a representation of logical time. In other words, the order of request validation on the server is very important. If you issue more that one signed request at the same time, then the order is not guaranteed and therefore one from the requests may fail. On top of that, Mobile SDK itself is using this type of signatures for its own purposes. For example, if you ask for token, then the SDK is using signed request to obtain the token's data. To deal with this problem, Mobile SDK is providing a custom serial `Executor`, which can be used for signed requests execution:

<!-- begin codetabs Kotlin Java -->
```kotlin
powerAuthSDK.serialExecutor.execute {
    // Recommended practice:
    // 1. You have to calculate PowerAuth signature here.
    // 2. In case that you start yet another asynchronous operation from run(),
    //    then you have to wait for that operation's execution.
}
```
```java
final Executor serialExecutor = powerAuthSDK.getSerialExecutor();
serialExecutor.execute(new Runnable() {
    @Override
    public void run() {
        // Recommended practice:
        // 1. You have to calculate PowerAuth signature here.
        // 2. In case that you start yet another asynchronous operation from run(),
        //    then you have to wait for that operation's execution.
    }
});
```
<!-- end -->

### Asymmetric Private Key Signature

Asymmetric Private Key Signature uses a private key stored in the PowerAuth secure vault. In order to unlock the secure vault and retrieve the private key, the user has to first authenticate using the symmetric multi-factor signature with at least two factors. This mechanism protects the private key on the device - the server plays a role of a "doorkeeper" and holds the vault unlock key.

This process is completely transparent on the SDK level. To compute an asymmetric private key signature, request user credentials (password, PIN, biometric image) and use the following code:

<!-- begin codetabs Kotlin Java -->
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
```java
// Prepare the authentication object
PowerAuthAuthentication authentication = PowerAuthAuthentication.possessionWithPassword("1234");

// Get the data to be signed
byte[] data = this.getMyData();

powerAuthSDK.signDataWithDevicePrivateKey(context, authentication, data, new IDataSignatureListener() {
    @Override
    public void onDataSignedSucceed(byte[] signature) {
        // Use data signature...
    }

    @Override
    public void onDataSignedFailed(Throwable t) {
        // Report error
    }
});
```
<!-- end -->

### Symmetric Offline Multi-Factor Signature

This type of signature is very similar to [Symmetric Multi-Factor Signature](#symmetric-multi-factor-signature) but the result is provided in the form of a simple, human-readable string (unlike the online version, where the result is HTTP header). To calculate the signature, you need a typical `PowerAuthAuthentication` object to define all required factors, nonce and data to sign. The `nonce` and `data` should also be transmitted to the application over the OOB channel (for example, by scanning a QR code). Then the signature calculation is straightforward:

<!-- begin codetabs Kotlin Java -->
```kotlin
// Prepare the authentication object
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")

val signature = powerAuthSDK.offlineSignatureWithAuthentication(context, authentication, "/confirm/offline/operation", data, nonce)
if (signature != null) {
    Log.d(TAG, "Offline signature is: $signature")
} else {
    // failure: session is probably invalid, or some required data is missing
}
```
```java
// Prepare the authentication object
PowerAuthAuthentication authentication = PowerAuthAuthentication.possessionWithPassword("1234");

final String signature = powerAuthSDK.offlineSignatureWithAuthentication(context, authentication, "/confirm/offline/operation", data, nonce);
if (signature != null) {
    android.util.Log.d(TAG, "Offline signature is: " + signature);
} else {
    // failure: session is probably invalid, or some required data is missing
}
```
<!-- end -->

The application has to show that calculated signature to the user now, and the user has to re-type that code into the web application for the verification.

<!-- begin box info -->
You can alter the lenght of the signature components by using `offlineSignatureComponentLength()` function of `PowerAuthConfiguration.Builder` class.
<!-- end -->

### Verify Server-Signed Data

This task is useful whenever you need to receive arbitrary data from the server and you need to be able to verify that the server has issued the data. The PowerAuthSDK provides a high-level method for validating data and associated signature:  

<!-- begin codetabs Kotlin Java -->
```kotlin
// Validate data signed with the master server key
if (powerAuthSDK.verifyServerSignedData(data, signature, true)) {
    // data is signed with server's private master key
}
// Validate data signed with the personalized server key
if (powerAuthSDK.verifyServerSignedData(data, signature, false)) {
    // data is signed with server's private key
}  
```
```java
// Validate data signed with the master server key
if (powerAuthSDK.verifyServerSignedData(data, signature, true)) {
    // data is signed with server's private master key
}
// Validate data signed with the personalized server key
if (powerAuthSDK.verifyServerSignedData(data, signature, false)) {
    // data is signed with server's private key
}
```
<!-- end -->

## Password Change

Since the device does not know the password and is unable to verify the password without the help of the server-side, you need to first call an endpoint that verifies a signature computed with the password. SDK offers two ways to do that.

The safe but typically slower way is to use the following code:

<!-- begin codetabs Kotlin Java -->
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
```java
// Change password from "oldPassword" to "newPassword".
powerAuthSDK.changePassword(context, "oldPassword", "newPassword", new IChangePasswordListener() {
    @Override
    public void onPasswordChangeSucceed() {
        // Password was changed
    }

    @Override
    public void onPasswordChangeFailed(Throwable t) {
        // Error occurred
    }
})
```
<!-- end -->

This method calls `/pa/v3/signature/validate` under the hood with a 2FA signature with provided original password to verify the password correctness.

However, using this method does not usually fit the typical UI workflow of a password change. The method may be used in cases where an old password and a new password are on a single screen, and therefore are both available at the same time. In most mobile apps, however, the user first visits a screen to enter an old password, and then (if the password is OK), the user proceeds to the two-screen flow of a new password setup (select password, confirm password). In other words, the workflow works like this:

1. Show a screen to enter an old password.
2. Check an old password on the server.
3. If the old password is OK, then let the user chose and confirm a new one.
4. Change the password by re-encrypting the activation data.

For this purpose, you can use the following code:

<!-- begin codetabs Kotlin Java -->
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
```java
// [1] Ask for an old password
String oldPassword = "1234";

// [2] Validate password on the server
powerAuthSDK.validatePassword(context, oldPassword, new IValidatePasswordListener() {
    @Override
    public void onPasswordValid() {
        // Proceed to the new password setup
    }

    @Override
    public void onPasswordValidationFailed(Throwable t) {
        // Retry entering an old password
    }
});

// [3] Ask for new password
String newPassword = "2468";

// [4] Change the password locally
powerAuthSDK.changePasswordUnsafe(oldPassword, newPassword);
```
<!-- end -->

<!-- begin box warning -->
**Now, beware!** Since the device does not know the actual old password, you need to make sure that the old password is validated before you use it in `unsafeChangePassword`. In case you provide the wrong old password, it will be used to decrypt the original data, and these data will be encrypted using a new password. As a result, the activation data will be broken and irreversibly lost.
<!-- end -->


## Working with passwords securely

PowerAuth mobile SDK uses `io.getlime.security.powerauth.core.Password` object behind the scene, to store user's password or PIN securely. The object automatically wipes out the plaintext password on its destroy, so there are no traces of sensitive data left in the memory. You can easily enhance your application's runtime security by adopting this object in your code and this chapter explains in detail how to do it.

### Problem explanation

If you store the user's password in simple string, there is a high probabilty that the content of the string will remain in the memory until the same region is reused by the underlying memory allocator. This is due the fact that the general memory allocator doesn't cleanup the region of memory being freed. It just update its linked-list of free memory regions for future reuse, so the content of allocated object typically remains intact. This has the following implications to your application:

- If your application is using system keyboard to enter the password or PIN, then the sensitive data will remain in memory in multiple copies for a while. 

- If the device's memory is not stressed enough, then the application may remain in memory active for days.

The situation that the user's password stays in memory for days may be critical in situations when the attacker has the device in possession. For example, if device is lost or is in repair shop. To minimize the risks, the `Password` object does the following things:

- Always keeps user's password scrambled with a random data, so it cannot be easily found by simple string search. The password in plaintext is revealed only for a short and well defined time when it's needed for the cryptographic operation.

- Always clears buffer with the sensitive data before the object's destruction.

- Doesn't provide a simple interface to reveal the password in plaintext<sup>1)</sup> and therefore it minimizes the risks of revealing the password by accident (like print it to the log).

<!-- begin box info -->
**Note 1:** There's `validatePasswordComplexity()` function that reveal the password in plaintext for the limited time for the complexity validation purposes. The straightforward naming of the function allows you to find all its usages in your code and properly validate all codepaths.
<!-- end -->

### Special password object usage

PowerAuth mobile SDK allows you to use both strings and special password objects at input, so it's up to you which way fits best for your purposes. For simplicity, this documentation is using strings for the passwords, but all code examples can be changed to utilize `Password` object as well. For example, this is the modified code for [Password Change](#password-change):

<!-- begin codetabs Kotlin Java -->
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
```java
// Change password from "oldPassword" to "newPassword".
Password oldPass = new Password("oldPassword");
Password newPass = new Password("newPassword")
powerAuthSDK.changePassword(context, oldPass, newPass, new IChangePasswordListener() {
    @Override
    public void onPasswordChangeSucceed() {
        // Password was changed
    }

    @Override
    public void onPasswordChangeFailed(Throwable t) {
        // Error occurred
    }
})
```
<!-- end -->


### Entering PIN

If your application is using system numberic keyboard to enter user's PIN then you can migrate to `Password` object right now. We recommend you to do the following things:

- Implement your own PIN keyboard UI

- Make sure that password object is allocated and referenced only in the PIN keyboard controller and is deallocated when user leaves the controller.

- Use `Password()` object that allows you to manipulate with the content of the PIN 

Here's the simple pseudo-controller example:

```kotlin
class EnterPinScene(val desiredPinLength: Int = 4) {

    private var pinInstance: Password? = null
    private val pin: Password get() = pinInstance ?: throw IllegalStateException()

    fun onEnterScene() {
        // Allocate password when entering to the scene.
        // Constructor with no parameters create mutable Password.
        pinInstance = Password()
    }

    fun onLeaveScene() {
        // Dereference and destroy the password object, when user is leaving
        // the scene to safely wipe the content out of the memory.
        //
        // Make sure that this is done only after PowerAuth SDK finishes all operations
        // started with this object at input.
        pinInstance?.destroy()
        pinInstance = null
    }

    fun onDeleteButtonAction() {
        pin.removeLastCharacter()
    }

    fun onPinButtonAction(pinCharacter: Char) {
        // Mutable password works with unicode scalars, this is the example
        // that works with an arbitrary character up to code-point 0xFFFF.
        // To add an arbitrary unicode character, you need to convert it to code point first.
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
        // Do something with entered pin...
    }
}
```

### Entering arbitrary password

Unfortunately, there's no simple solution for this scenario. It's quite difficult to re-implement the whole keyboard on your own, so we recommend you to keep using the system keyboard. You can still create the `Password` object from already entered string:

<!-- begin codetabs Kotlin Java -->
```kotlin
val passwordString = "nbusr123"
val password = Password(passwordString)
```
```java
final String passwordString = "nbusr123";
final Password password = new Password(passwordString);
```
<!-- end -->

### Create password from data

In case that passphrase is somehow created externally in form of array of bytes, then you can instantiate it from the `Data` object directly:

<!-- begin codetabs Kotlin Java -->
```kotlin
val passwordData = Base64.decode("bmJ1c3IxMjMK", Base64.NO_WRAP)
val password = Password(passwordData)
```
```java
final byte[] passwordData = Base64.decode("bmJ1c3IxMjMK", Base64.NO_WRAP);
final Password password = new Password(passwordData);
```
<!-- end -->


### Compare two passwords

To compare two passwords, use `isEqual(to:)` method:

<!-- begin codetabs Kotlin Java -->
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
```java
final Password password1 = new Password("1234")
final Password password2 = new Password("Hello")
final Password password3 = new Password()
password3.addCharacter(0x31)
password3.addCharacter(0x32)
password3.addCharacter(0x33)
password3.addCharacter(0x34)
Log.d("TAG", (password1.isEqualToPassword(password2)).toString())  // false
Log.d("TAG", (password1.equals(password2)).toString())             // true
```
<!-- end -->

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


## Biometric Authentication Setup

PowerAuth SDK for Android provides an abstraction on top of the base Biometric Authentication support. While the authentication / data signing itself is handled using the `PowerAuthAuthentication` object used in [regular request signing](#data-signing), other biometry-related processes require their own API.

### Check Biometric Authentication Status

You have to check for Biometric Authentication on three levels:

- **System Availability**: If biometric scanner is present on the system.
- **Activation Availability**: If biometry factor data are available for given activation.
- **Application Availability**: If user decided to use biometric authentication for given app. _(optional)_

PowerAuth SDK for Android provides code for the first and second of these checks.

To check if you can use the biometric authentication, use our helper class:

<!-- begin codetabs Kotlin Java -->
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
        // It's not possible to determine exact type of biometry.
        // This happens on Android 10+ systems, when the device supports
        // more than one type of biometric authentication. In this case,
        // you should use generic terms, like "Authenticate with biometry"
        // for your UI.
        print("Biometry type is GENERIC")
    BiometryType.FINGERPRINT ->
        print("Fingerprint scanner is present on the device.")
    BiometryType.FACE ->
        print("Face scanner is present on the device.")
    BiometryType.IRIS ->
        print("Iris scanner is present on the device.")
}
```
```java
// This method is equivalent to `BiometricManager.canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS`.
// Use it to check if the biometric authentication can be used at the moment.
boolean isBiometricAuthAvailable = BiometricAuthentication.isBiometricAuthenticationAvailable(context);

// For more fine-grained control about the actual biometric authentication status,
// you may use the following code:
switch (BiometricAuthentication.canAuthenticate(context)) {
    case BiometricStatus.OK:
        // everything's OK
    case BiometricStatus.NOT_SUPPORTED:
        // device's hardware doesn't support biometry
    case BiometricStatus.NOT_ENROLLED:
        // there's no biometry data enrolled on the device
    case BiometricStatus.NOT_AVAILABLE:
        // The biometric authentication is not available at this time.
        // You may try to retry the operation later.
}

// If you want to adjust localized strings or icons presented to the user,
// you can use the following code to determine the type of biometry available
// on the system:
switch (BiometricAuthentication.getBiometryType(context)) {
    case BiometryType.NONE:
        // Biometry is not supported on the system.
    case BiometryType.GENERIC:
        // It's not possible to determine exact type of biometry.
        // This happens on Android 10+ systems, when the device supports
        // more than one type of biometric authentication. In this case,
        // you should use generic terms, like "Authenticate with biometry"
        // for your UI.
    case BiometryType.FINGERPRINT:
        // Fingerprint scanner is present on the device.
    case BiometryType.FACE:
        // Face scanner is present on the device.
    case BiometryType.IRIS:
        // Iris scanner is present on the device.
}
```
<!-- end -->

To check if a given activation has biometry factor-related data available, use the following code:

<!-- begin codetabs Kotlin Java -->
```kotlin
// Does activation have biometric factor-related data in place?
val hasBiometryFactor = powerAuthSDK.hasBiometryFactor(context)
```
```java
// Does activation have biometric factor-related data in place?
boolean hasBiometryFactor = powerAuthSDK.hasBiometryFactor(context);
```
<!-- end -->

The last check is fully under your control. By keeping the biometric settings flag, for example, a `BOOL` in `SharedPreferences`, you are able to show user an expected biometric authentication status (in a disabled state, though) even in the case biometric authentication is not enabled or when no fingers are enrolled on the device.

### Enable Biometric Authentication

In case an activation does not yet have biometry-related factor data, and you would like to enable biometric authentication support, the device must first retrieve the original private key from the secure vault for the purpose of key derivation. As a result, you have to use a successful 2FA with a password to enable biometric authentication support.

Use the following code to enable biometric authentication using biometric authentication:

<!-- begin codetabs Kotlin Java -->
```kotlin
// Establish biometric data using provided password
powerAuthSDK.addBiometryFactor(context, fragment, "Enable Biometric Authentication", "To enable biometric authentication, use the biometric sensor on your device.", "1234", object: IAddBiometryFactorListener {
    override fun onAddBiometryFactorSucceed() {
        // Everything went OK, biometric authentication is ready to be used
    }

    override fun onAddBiometryFactorFailed(error: PowerAuthErrorException) {
        // Error occurred, report it to user
    }
})
```
```java
// Establish biometric data using provided password
powerAuthSDK.addBiometryFactor(context, fragment, "Enable Biometric Authentication", "To enable biometric authentication, use the biometric sensor on your device.", "1234", new IAddBiometryFactorListener() {
    @Override
    public void onAddBiometryFactorSucceed() {
        // Everything went OK, biometric authentication is ready to be used
    }

    @Override
    public void onAddBiometryFactorFailed(@NonNull PowerAuthErrorException error) {
        // Error occurred, report it to user
    }
});
```
<!-- end -->

By default, PowerAuth SDK asks user to authenticate with the biometric sensor also during the setup procedure (or during the [activation commit](#committing-activation-data)). To alter this behavior, use the following code to change `PowerAuthKeychainConfiguration` provided to `PowerAuthSDK` instance:

<!-- begin codetabs Kotlin Java -->
```kotlin
val keychainConfig = PowerAuthKeychainConfiguration.Builder()
    .authenticateOnBiometricKeySetup(false)
    .build()
// Apply keychain configuration
val powerAuthSDK = PowerAuthSDK.Builder(configuration)
    .keychainConfiguration(keychainConfig)
    .build(getApplicationContext())
```
```java
PowerAuthKeychainConfiguration keychainConfig = new PowerAuthKeychainConfiguration.Builder()
        .authenticateOnBiometricKeySetup(false)
        .build();
// Apply keychain configuration
PowerAuthSDK powerAuthSDK = new PowerAuthSDK.Builder(configuration)
        .keychainConfiguration(keychainConfig)
        .build(getApplicationContext());
```
<!-- end -->

<!-- begin box info -->
Note that the RSA key-pair is internally generated for the configuration above. That may take more time on older devices than the default configuration. Your application should display a waiting indicator on its own, because SDK doesn't display an authentication dialog during the key-pair generation.
<!-- end -->

### Disable Biometric Authentication

You can remove biometry related factor data used by biometric authentication support by simply removing the related key locally, using this one-liner:

<!-- begin codetabs Kotlin Java -->
```kotlin
powerAuthSDK.removeBiometryFactor(context)
```
```java
// Remove biometric data
powerAuthSDK.removeBiometryFactor(context);
```
<!-- end -->

### Fetching the Biometry Factor-Related Key for Authentication

In order to obtain an encrypted biometry factor-related key for the purpose of authentication, call the following code:

<!-- begin codetabs Kotlin Java -->
```kotlin
// Authenticate user with biometry and obtain encrypted biometry factor related key.
powerAuthSDK.authenticateUsingBiometry(context, fragment, "Sign in", "Use the biometric sensor on your device to continue", object: IBiometricAuthenticationCallback {
    override fun onBiometricDialogCancelled(userCancel: Boolean) {
        // User cancelled the operation
    }

    override fun onBiometricDialogSuccess(biometricKeyData: BiometricKeyData) {
        // User authenticated and biometry key was returned, now you can construct PowerAuthAuthentication object with proper signing capabilities.
        val biometryFactorRelatedKey = biometricKeyData.derivedData
        val twoFactorBiometry = PowerAuthAuthentication.possessionWithBiometry(biometryFactorRelatedKey)
    }

    override fun onBiometricDialogFailed(error: PowerAuthErrorException) {
        // Biometric authentication failed
    }
})
```
```java
// Authenticate user with biometry and obtain encrypted biometry factor related key.
powerAuthSDK.authenticateUsingBiometry(context, fragment, "Sign in", "Use the biometric sensor on your device to continue", new IBiometricAuthenticationCallback() {
    @Override
    public void onBiometricDialogCancelled(boolean userCancel) {
        // User cancelled the operation
    }

    @Override
    public void onBiometricDialogSuccess(BiometricKeyData biometricKeyData) {
        // User authenticated and biometry key was returned, now you can construct PowerAuthAuthentication object with proper signing capabilities.
        final byte[] biometryFactorRelatedKey = biometricKeyData.getDerivedData();
        final PowerAuthAuthentication twoFactorBiometry = PowerAuthAuthentication.possessionWithBiometry(biometryFactorRelatedKey);
    }

    @Override
    public void onBiometricDialogFailed(PowerAuthErrorException error) {
        // Biometric authentication failed
    }
});
```
<!-- end -->

<!-- begin box warning -->
Note that if the biometric authentication fails with too many attempts in a row (e.g. biometry is temporarily or permanently locked out), then PowerAuth SDK will generate an invalid biometry factor related key and the success is reported. This is an intended behavior and as the result, it typically lead to unsuccessful authentication on the server and increased counter of failed attempts. The purpose of this is to limit the number of attempts for attacker to deceive the biometry sensor.
<!-- end -->

### Biometry Factor-Related Key Lifetime

By default, the biometry factor-related key is invalidated after the biometry enrolled in the system is changed. For example, if the user adds or removes the finger or enrolls with a new face, then the biometry factor-related key is no longer available for the signing operation. To change this behavior, you have to provide `PowerAuthKeychainConfiguration` object with `linkBiometricItemsToCurrentSet` parameter set to `false` and use that configuration for the `PowerAuthSDK` instance construction:

<!-- begin codetabs Kotlin Java -->
```kotlin
// Use false for 'linkBiometricItemsToCurrentSet' parameter.
val keychainConfig = PowerAuthKeychainConfiguration.Builder()
    .linkBiometricItemsToCurrentSet(false)
    .build()
// Apply keychain configuration
val powerAuthSDK = PowerAuthSDK.Builder(configuration)
    .keychainConfiguration(keychainConfig)
    .build(getApplicationContext())
```
```java
// Use false for 'linkBiometricItemsToCurrentSet' parameter.
PowerAuthKeychainConfiguration keychainConfig = new PowerAuthKeychainConfiguration.Builder()
            .linkBiometricItemsToCurrentSet(false)
            .build();
// Apply keychain configuration
PowerAuthSDK powerAuthSDK = new PowerAuthSDK.Builder(configuration)
        .keychainConfiguration(keychainConfig)
        .build(getApplicationContext());
```
<!-- end -->

Be aware that the configuration above is effective only for the new keys. So, if your application is already using the biometry factor-related key with a different configuration, then the configuration change doesn't change the existing key. You have to [disable](#disable-biometric-authentication) and [enable](#enable-biometric-authentication) biometry to apply the change.

### Biometric Authentication Details

The `BiometricAuthentication` class is a high level interface that provides interfaces related to the biometric authentication for the SDK, or for the application purposes. The class hides all technical details, so it can be safely used also on the systems that doesn't provide biometric interfaces, or if the system has no biometric sensor available. The implementation under the hood uses `androidx.biometric.BiometricPrompt` and `androidx.biometric.BiometricManager` classes.

To customize the strings used in biometric authentication, you can use `BiometricDialogResources` in the following manner:

<!-- begin codetabs Kotlin Java -->
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
```java
// Prepare new strings, colors, etc...
final BiometricDialogResources.Strings newStrings = new BiometricDialogResources.Strings(... constructor with string ids ...);

// Build new resources object.
// If you omit some custom resources object, then the Builder will replace that with resources bundled in SDK.
final BiometricDialogResources resources = new BiometricDialogResources.Builder()
                                            .setStrings(newStrings)
                                            .build();

// Set resources to BiometricAuthentication
BiometricAuthentication.setBiometricDialogResources(resources);
```
<!-- end -->

On Android 10+ systems, it's possible to configure `BiometricPrompt` to ask for an additional confirmation after the user is successfully authenticated. The default behavior for PowerAuth Mobile SDK is that such confirmation is not required. To change this behavior, you have to provide `PowerAuthKeychainConfiguration` object with `confirmBiometricAuthentication` parameter set to `true` and use that configuration for the `PowerAuthSDK` instance construction:

<!-- begin codetabs Kotlin Java -->
```kotlin
// Use true for 'confirmBiometricAuthentication' parameter.
val keychainConfig = PowerAuthKeychainConfiguration.Builder()
    .confirmBiometricAuthentication(true)
    .build()
// Apply keychain configuration
val powerAuthSDK = PowerAuthSDK.Builder(configuration)
    .keychainConfiguration(keychainConfig)
    .build(context)
```
```java
// Use true for 'confirmBiometricAuthentication' parameter.
PowerAuthKeychainConfiguration keychainConfig = new PowerAuthKeychainConfiguration.Builder()
        .confirmBiometricAuthentication(true)
        .build();
// Apply keychain configuration
PowerAuthSDK powerAuthSDK = new PowerAuthSDK.Builder(configuration)
        .keychainConfiguration(keychainConfig)
        .build(getApplicationContext());
```
<!-- end -->

## Activation Removal

You can remove activation using several ways - the choice depends on the desired behavior.

### Simple Device-Only Removal

You can clear activation data anytime from the `SharedPreferences`. The benefit of this method is that it does not require help from the server, and the user does not have to be logged in. The issue with this removal method is simple: The activation still remains active on the server-side. This, however, does not have to be an issue in your case.

To remove only data related to PowerAuth SDK for Android, use the following code:

<!-- begin codetabs Kotlin Java -->
```kotlin
powerAuthSDK.removeActivationLocal(context)
```
```java
powerAuthSDK.removeActivationLocal(context);
```
<!-- end -->

### Removal via Authenticated Session

Suppose your server uses an authenticated session for keeping the users logged in. In that case, you can combine the previous method with calling your proprietary endpoint to remove activation for the currently logged-in user. The advantage of this method is that activation does not remain active on the server. The issue is that the user has to be logged in (the session must be active and must have activation ID stored) and that you have to publish your own method to handle this use case.

The code for this activation removal method is as follows:

<!-- begin codetabs Kotlin Java -->
```kotlin
// Use custom call to proprietary server endpoint to remove activation.
// User must be logged in at this moment, so that session can find
// associated activation ID
this.httpClient.post(null, "/custom/activation/remove", object: ICustomListener {
    override fun onSucceed() {
        powerAuthSDK.removeActivationLocal(context)
    }
    
    override fun onFailed(t: Throwable) {
        // Error occurred, report it to user
    }
})
```
```java
// Use custom call to proprietary server endpoint to remove activation.
// User must be logged in at this moment, so that session can find
// associated activation ID
this.httpClient.post(null, "/custom/activation/remove", new ICustomListener() {
    @Override
    public void onSucceed() {
        powerAuthSDK.removeActivationLocal(context);
    }

    @Override
    public void onFailed(Throwable t) {
        // Error occurred, report it to user
    }
});
```
<!-- end -->

### Removal via Signed Request

PowerAuth Standard RESTful API has a default endpoint `/pa/v3/activation/remove` for an activation removal. This endpoint uses a signature verification for looking up the activation to be removed. The benefit of this method is that it is already present in both PowerAuth SDK for Android and PowerAuth Standard RESTful API - nothing has to be programmed. Also, the user does not have to be logged in to use it. However, the user has to authenticate using 2FA with either password or biometric authentication.

Use the following code for an activation removal using signed request:

<!-- begin codetabs Kotlin Java -->
```kotlin
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")

// Remove activation using provided authentication object
powerAuthSDK.removeActivationWithAuthentication(context, authentication, object: IActivationRemoveListener {
    override fun onActivationRemoveSucceed() {
        // OK, activation was removed
    }

    override fun onActivationRemoveFailed(t: Throwable) {
        // Report error to user
    }
})
```
```java
PowerAuthAuthentication authentication = PowerAuthAuthentication.possessionWithPassword("1234");

// Remove activation using provided authentication object
powerAuthSDK.removeActivationWithAuthentication(context, authentication, new IActivationRemoveListener() {
    @Override
    public void onActivationRemoveSucceed() {
        // OK, activation was removed
    }

    @Override
    public void onActivationRemoveFailed(Throwable t) {
        // Report error to user
    }
})
```
<!-- end -->

## End-To-End Encryption

Currently, PowerAuth SDK supports two basic modes of end-to-end encryption, based on the ECIES scheme:

- In an "application" scope, the encryptor can be acquired and used during the whole lifetime of the application.
- In an "activation" scope, the encryptor can be acquired only if `PowerAuthSDK` has a valid activation. The encryptor created for this mode is cryptographically bound to the parameters agreed during the activation process. You can combine this encryption with [PowerAuth Symmetric Multi-Factor Signature](#symmetric-multi-factor-signature) in "encrypt-then-sign" mode.


For both scenarios, you need to acquire `EciesEncryptor` object, which will then provide interface for the request encryption and the response decryption. The object currently provides only low level encryption and decryption methods, so you need to implement your own JSON (de)serialization and request and response processing.

The following steps are typically required for a full E2EE request and response processing:

1. Acquire the right encryptor from the `PowerAuthSDK` instance. For example:
   ```kotlin
   // Encryptor for "application" scope.
   val encryptor = powerAuthSDK.eciesEncryptorForApplicationScope
   // ...or similar, for an "activation" scope.
   val encryptor = powerAuthSDK.getEciesEncryptorForActivationScope(context)
   ```

1. Serialize your request payload, if needed, into a sequence of bytes. This step typically means that you need to serialize your model object into a JSON formatted sequence of bytes.

1. Make sure that PowerAuth SDK instance has [time synchronized with the server](#synchronized-time):
   ```kotlin
   val timeService = powerAuthSDK.timeSynchronizationService
   if (!timeService.isTimeSynchronized) {
       timeService.synchronizeTime(object : ITimeSynchronizationListener {
           override fun onTimeSynchronizationSucceeded() {
               // Success
           }

           override fun onTimeSynchronizationFailed(t: Throwable) {
               // Failure
           }
       })
   }
   ```

1. Encrypt your payload:
   ```kotlin
   val cryptogram = encryptor.encryptRequest(payloadData)
   if (cryptogram == null) {
       // cannot encrypt data
   }  
   ```

1. Construct a JSON from provided cryptogram object. The dictionary with the following keys is expected:
   - `ephemeralPublicKey` property fill with `cryptogram.getKeyBase64()`
   - `encryptedData` property fill with `cryptogram.getBodyBase64()`
   - `mac` property fill with `cryptogram.getMacBase64()`
   - `nonce` property fill with `cryptogram.getNonceBase64()`
   - `timestamp` property fill with `cryptogram.getTimestamp()`

   So, the final request JSON should look like this:
   ```json
   {
      "ephemeralPublicKey" : "BASE64-DATA-BLOB",
      "encryptedData": "BASE64-DATA-BLOB",
      "mac" : "BASE64-DATA-BLOB",
      "nonce" : "BASE64-NONCE",
      "timestamp" : 1694172789256
   }
   ```

1. Add the following HTTP header (for signed requests, see note below):
   ```kotlin
   // Acquire a "metadata" object, which contains additional information for the request construction
   val metadata = encryptor.metadata
   val httpHeaderName = metadata.httpHeaderKey
   val httpHeaderValue = metadata.httpHeaderValue
   ```
   Note, that if an "activation" scoped encryptor is combined with PowerAuth Symmetric Multi-Factor signature, then this step is not required. The signature's header already contains all information required for proper request decryption on the server.

1. Fire your HTTP request and wait for a response
   - In case that non-200 HTTP status code is received, then the error processing is identical to a standard RESTful response defined in our protocol. So, you can expect a JSON object with `"error"` and `"message"` properties in the response.

1. Decrypt the response. The received JSON typically looks like this:
   ```json
   {
      "encryptedData": "BASE64-DATA-BLOB",
      "mac" : "BASE64-DATA-BLOB",
      "nonce" : "BASE64-NONCE",
      "timestamp" : 1694172789256
   }
   ```
   
   So, you need to create yet another "cryptogram" object, but with only two properties set:
   ```kotlin
   val responseCryptogram = EciesCryptogram(response.encryptedData, response.mac)
   val responseData = encryptor.decryptResponse(responseCryptogram)
   if (responseData == null) {
       // failed to decrypt response data
   }
   ```

1. And finally, you can process your received response.

As you can see, the E2EE is quite a non-trivial task. We recommend contacting us before using an application-specific E2EE. We can provide you more support on a per-scenario basis, especially if we first understand what you try to achieve with end-to-end encryption in your application.


## Secure Vault

PowerAuth SDK for Android has basic support for an encrypted secure vault. At this moment, the only supported method allows your application to establish an encryption / decryption key with a given index. The index represents a "key number" - your identifier for a given key. Different business logic purposes should have encryption keys with a different index value.

On a server side, all secure vault related work is concentrated in a `/pa/v3/vault/unlock` endpoint of PowerAuth Standard RESTful API. In order to receive data from this response, call must be authenticated with at least 2FA (using password or PIN).

<!-- begin box warning -->
Secure vault mechanism does not support biometry by default. Use PIN code or password based authentication for unlocking the secure vault, or ask your server developers to enable biometry for vault unlock call by configuring PowerAuth Server instance.
<!-- end -->

### Obtaining Encryption Key

In order to obtain an encryption key with a given index, use the following code:

<!-- begin codetabs Kotlin Java -->
```kotlin
// 2FA signature. It uses device related key and user PIN code.
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")

// Select custom key index
val index = 1000L

// Fetch encryption key with given index
powerAuthSDK.fetchEncryptionKey(context, authentication, index, object: IFetchEncryptionKeyListener {
    override fun onFetchEncryptionKeySucceed(encryptedEncryptionKey: ByteArray) {
        // ... use encryption key to encrypt or decrypt data
    }

    override fun onFetchEncryptionKeyFailed(t: Throwable) {
        // Report error
    }
})
```
```java
// 2FA signature. It uses device related key and user PIN code.
PowerAuthAuthentication authentication = PowerAuthAuthentication.possessionWithPassword("1234");

// Select custom key index
long index = 1000L;

// Fetch encryption key with given index
powerAuthSDK.fetchEncryptionKey(context, authentication, index, new IFetchEncryptionKeyListener() {
    @Override
    public void onFetchEncryptionKeySucceed(byte[] encryptedEncryptionKey) {
        // ... use encryption key to encrypt or decrypt data
    }

    @Override
    public void onFetchEncryptionKeyFailed(Throwable t) {
        // Report error
    }
})
```
<!-- end -->

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

<!-- begin codetabs Kotlin Java -->
```kotlin
if (!powerAuthSDK.hasActivationRecoveryData()) {
    // Recovery information is not available
    return
}

// 2FA signature, uses device related key and user PIN code
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")

powerAuthSDK.getActivationRecoveryData(context, authentication, object: IGetRecoveryDataListener {
    override fun onGetRecoveryDataSucceeded(recoveryData: RecoveryData) {
        val recoveryCode = recoveryData.recoveryCode
        val puk = recoveryData.puk
        // Show values on the screen...
    }

    override fun onGetRecoveryDataFailed(t: Throwable) {
        // Report error
    }
})
```
```java
if (!powerAuthSDK.hasActivationRecoveryData()) {
    // Recovery information is not available
    return;
}

// 2FA signature, uses device related key and user PIN code
PowerAuthAuthentication authentication = PowerAuthAuthentication.possessionWithPassword("1234");

powerAuthSDK.getActivationRecoveryData(context, authentication, new IGetRecoveryDataListener() {
    @Override
    public void onGetRecoveryDataSucceeded(RecoveryData recoveryData) {
        final String recoveryCode = recoveryData.recoveryCode;
        final String puk = recoveryData.puk;
        // Show values on the screen...
    }

    @Override
    public void onGetRecoveryDataFailed(Throwable t) {
        // Report error
    }
});
```
<!-- end -->

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

<!-- begin codetabs Kotlin Java -->
```kotlin
// 2FA signature with possession factor is required
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")
val recoveryCode = "VVVVV-VVVVV-VVVVV-VTFVA" // You can also use code scanned from QR
powerAuthSDK.confirmRecoveryCode(context, authentication, recoveryCode, object: IConfirmRecoveryCodeListener {
    override fun onRecoveryCodeConfirmed(alreadyConfirmed: Boolean) {
        if (alreadyConfirmed) {
            android.util.Log.d(TAG, "Recovery code has been already confirmed. This is not an error, just information.")
        } else {
            android.util.Log.d(TAG, "Recovery code has been successfully confirmed.")
        }
    }

    override fun onRecoveryCodeConfirmFailed(t: Throwable) {
        // Report error
    }
})
```
```java
// 2FA signature with possession factor is required
final PowerAuthAuthentication authentication = PowerAuthAuthentication.possessionWithPassword("1234");
final String recoveryCode = "VVVVV-VVVVV-VVVVV-VTFVA" // You can also use code scanned from QR
powerAuthSDK.confirmRecoveryCode(context, authentication, recoveryCode, new IConfirmRecoveryCodeListener{
    @Override
    public void onRecoveryCodeConfirmed(boolean alreadyConfirmed) {
        if (alreadyConfirmed) {
            android.util.Log.d(TAG, "Recovery code has been already confirmed. This is not an error, just information.");
        } else {
            android.util.Log.d(TAG, "Recovery code has been successfully confirmed.");
        }
    }

    @Override
    public void onRecoveryCodeConfirmFailed(Throwable t) {
        // Report error
    }
});
```
<!-- end -->

The `alreadyConfirmed` boolean indicates that the code was already confirmed in the past. You can choose a different "success" screen, describing that the user has already confirmed such code. Also, note that codes bound to the activations are already confirmed.

## Token-Based Authentication

<!-- begin box warning -->
**WARNING:** Before you start using access tokens, please visit our [wiki page for powerauth-crypto](https://github.com/wultra/powerauth-crypto/blob/develop/docs/MAC-Token-Based-Authentication.md) for more information about this feature.
<!-- end -->

The tokens are simple, locally cached objects, producing timestamp-based authorization headers. Be aware that tokens are NOT a replacement for general PowerAuth signatures. They are helpful in situations when the signatures are too heavy or too complicated for implementation. Each token has the following properties:

- It needs PowerAuth signature for its creation (e.g., you need to provide `PowerAuthAuthentication` object)
- It has a unique identifier on the server. This identifier is not exposed to the public API, but you can reveal that value in the debugger.
- It has symbolic name (e.g., "MyToken") defined by the application programmer to identify already created tokens.
- It can generate timestamp-based authorization HTTP headers.
- It can be used concurrently. Token's private data doesn't change in time.
- The token is associated with the `PowerAuthSDK` instance. So, you can use the same symbolic name in multiple SDK instances, and each created token will be unique.
- Tokens are persisted in the `KeychainFactory` service and cached in the memory.
- Once the parent `PowerAuthSDK` instance loses its activation, all its tokens are removed from the local database.

### Getting Token

To get an access token, you can use the following code:

<!-- begin codetabs Kotlin Java -->
```kotlin
// 1FA signature, uses device related key
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
```java
// 1FA signature, uses device related key
final PowerAuthAuthentication authentication = PowerAuthAuthentication.possession();
final PowerAuthTokenStore tokenStore = powerAuthSDK.getTokenStore();
final ICancelable task = tokenStore.requestAccessToken(context, "MyToken", authentication, new IGetTokenListener() {
    @Override
    public void onGetTokenSucceeded(@NonNull PowerAuthToken powerAuthToken) {
        // the token has been successfully acquired
    }

    @Override
    public void onGetTokenFailed(@NonNull Throwable throwable) {
        // an error occurred
    }
});
```
<!-- end -->

The request is performed synchronously or asynchronously depending on whether the token is locally cached on the device. You can test this situation by calling `tokenStore.hasLocalToken(context, "MyToken")`. If operation is asynchronous, then `requestAccessToken()` returns cancellable task.

### Generating Authorization Header
Use the following code to generate an authorization header:

```kotlin
val task = tokenStore.generateAuthorizationHeader(context, "MyToken", object : IGenerateTokenHeaderListener {
    override fun onGenerateTokenHeaderSucceeded(header: PowerAuthAuthorizationHttpHeader) {
        val httpHeaderKey = header.key
        val httpHeaderValue = header.value
    }

    override fun onGenerateTokenHeaderFailed(t: Throwable) {
        // Failure
    }
})
```

Once you have a `PowerAuthToken` object, then you can use also a synchronous code to generate an authorization header:

<!-- begin codetabs Kotlin Java -->
```kotlin
val header: PowerAuthAuthorizationHttpHeader = token.generateHeader()
if (header.isValid) {
    // Header is valid, you can construct HTTP header...
    val httpHeaderKey = header.key
    val httpHeaderValue = header.value
} else {
    // handle error
}
```
```java
PowerAuthAuthorizationHttpHeader header = token.generateHeader();
if (header.isValid()) {
    // Header is valid, you can construct HTTP header...
    String httpHeaderKey = header.key;
    String httpHeaderValue = header.value;
} else {
    // handle error
}
```
<!-- end -->

<!-- begin box warning -->
The synchronous example above is safe to use only if you're sure that the time is already [synchronized with the server](#synchronized-time).
<!-- end -->

### Removing Token From the Server

To remove the token from the server, you can use the following code:

<!-- begin codetabs Kotlin Java -->
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
```java
powerAuthSDK.getTokenStore().removeAccessToken(context, "MyToken", new IRemoveTokenListener() {
    @Override
    public void onRemoveTokenSucceeded() {
        android.util.Log.d(TAG, "Token has been removed");
    }

    @Override
    public void onRemoveTokenFailed(@NonNull Throwable t) {
        // handle HTTP error
    }
});
```
<!-- end -->

### Removing Token Locally

To remove token locally, you can simply use the following code:

<!-- begin codetabs Kotlin Java -->
```kotlin
// Remove just one token
powerAuthSDK.tokenStore.removeLocalToken(context, "MyToken")
// Remove all local tokens
powerAuthSDK.tokenStore.removeAllLocalTokens(context)
```
```java
// Remove just one token
powerAuthSDK.getTokenStore().removeLocalToken(context, "MyToken");
// Remove all local tokens
powerAuthSDK.getTokenStore().removeAllLocalTokens(context);
```
<!-- end -->

Note that by removing tokens locally, you will lose control of the tokens stored on the server.

## External Encryption Key

The `PowerAuthSDK` allows you to specify an external encryption key (called EEK in our terminology) that can additionally protect the knowledge and the biometry factor keys. This feature is typically used to create a chain of activations where one instance of `PowerAuthSDK` is primary and unlocks access to all secondary activations.

The external encryption key has to be set before the activation is created, or can be added later. The internal state of `PowerAuthSDK` contains information that the factor keys are protected with EEK, so EEK must be known at the time of PowerAuth signature is calculated. You have three options on how to configure the key:

1. Assign EEK into `PowerAuthConfiguration.Builder` at the time of `PowerAuthSDK` object creation.
   - This is the most convenient way of using EEK, but the key must be known at the time of `PowerAuthSDK` instantiation.
   - Once the `PowerAuthSDK` instance creates a new activation, then the factor keys will be automatically protected with EEK.
   
2. Use `PowerAuthSDK.setExternalEncryptionKey()` to set EEK after the `PowerAuthSDK` instance is created.
   - This is useful in case EEK is not known during the `PowerAuthSDK` instance creation.
   - You can set the key in any `PowerAuthSDK` state, but be aware that the method will fail in case the instance has a valid activation that doesn't use EEK.
   - It's safe to set the same EEK multiple times.

3. Use `PowerAuthSDK.addExternalEncryptionKey()` to add EEK and protect the factor keys in case that `PowerAuthSDK` has already a valid activation.
   - This method is useful in case `PowerAuthSDK` already has a valid activation, but it doesn't use EEK yet.
   - The method automatically adds EEK into the internal configuration structure, but be aware, that all future `PowerAuthSDK` usages (e.g. after app restart) require to set EEK by configuration, or by the `setExternalEncryptionKey()` method.

You can remove EEK from an existing activation if the key is no longer required. To do this, use `PowerAuthSDK.removeExternalEncryptionKey()` method. Be aware, that EEK must be set by configuration, or by the `setExternalEncryptionKey()` method before you call the remove method. You can also use the `PowerAuthSDK.hasExternalEncryptionKey()` function to test whether the key is already set and in use.


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

The time service provides an additional information about time, such as how precisely the time is synchronized with the server:

```kotlin
if (timeService.isTimeSynchronized) {
    val precision = timeService.localTimeAdjustmentPrecision
    println("Time is now synchronized with precision ${precision}")
}
```

The precision value represents a maximum absolute deviation of synchronized time against the actual time on the server. For example, a value `500` means that time provided by `currentTime` method may be 0.5 seconds ahead or behind of the actual time on the server. If the precision is not sufficient for your purpose, for example, if you need to display a real-time countdown in your application, then try to synchronize the time manually. The precision basically depends on how quickly is the synchronization response received and processed from the server. A faster response results in higher precision.

## Common SDK Tasks

### Error Handling

The PowerAuth SDK is using the following types of exceptions:

- `PowerAuthMissingConfigException` - is typically thrown immediately when `PowerAuthSDK` instance is initialized with an invalid configuration.
- `FailedApiException` - is typically returned to callbacks when an asynchronous HTTP request ends on error.
- `ErrorResponseApiException` - is typically returned to callbacks when an asynchronous HTTP request ends on error and the error model object is present in the response.
- `PowerAuthErrorException` - typically covers all other erroneous situations. You can investigate a detailed reason of failure by getting the integer, from set of `PowerAuthErrorCodes` constants.

Here's an example for a typical error handling procedure:

<!-- begin codetabs Kotlin Java -->
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
            PowerAuthErrorCodes.BIOMETRY_NOT_RECOGNIZED -> Log.d(TAG, "The biometric authentication did not recognize the biometric image (fingerprint, face, etc...)")
            PowerAuthErrorCodes.BIOMETRY_LOCKOUT -> Log.d(TAG, "The biometric authentication is locked out due to too many failed attempts.")
            PowerAuthErrorCodes.OPERATION_CANCELED -> Log.d(TAG, "Error code for cancelled operations")
            PowerAuthErrorCodes.ENCRYPTION_ERROR -> Log.d(TAG, "Error code for errors related to end-to-end encryption")
            PowerAuthErrorCodes.INVALID_TOKEN -> Log.d(TAG, "Error code for errors related to token based auth.")
            PowerAuthErrorCodes.PROTOCOL_UPGRADE -> Log.d(TAG, "Error code for error that occurs when protocol upgrade fails at unrecoverable error.")
            PowerAuthErrorCodes.PENDING_PROTOCOL_UPGRADE -> Log.d(TAG, "The operation is temporarily unavailable, due to pending protocol upgrade.")
            PowerAuthErrorCodes.TIME_SYNCHRONIZATION -> Log.d(TAG, "Failed to synchronize time with the server.")
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
```java
Throwable t; // reported in asynchronous callback
if (t instanceof PowerAuthErrorException) {
    switch (((PowerAuthErrorException) t).getPowerAuthErrorCode()) {
        case PowerAuthErrorCodes.NETWORK_ERROR:
            android.util.Log.d(TAG, "Error code for error with network connectivity or download"); break;
        case PowerAuthErrorCodes.SIGNATURE_ERROR:
            android.util.Log.d(TAG,"Error code for error in signature calculation"); break;
        case PowerAuthErrorCodes.INVALID_ACTIVATION_STATE:
            android.util.Log.d(TAG,"Error code for error that occurs when activation state is invalid"); break;
        case PowerAuthErrorCodes.INVALID_ACTIVATION_DATA:
            android.util.Log.d(TAG,"Error code for error that occurs when activation data is invalid"); break;
        case PowerAuthErrorCodes.MISSING_ACTIVATION:
            android.util.Log.d(TAG,"Error code for error that occurs when activation is required but missing"); break;
        case PowerAuthErrorCodes.PENDING_ACTIVATION:
            android.util.Log.d(TAG,"Error code for error that occurs when pending activation is present and work with completed activation is required"); break;
        case PowerAuthErrorCodes.INVALID_ACTIVATION_CODE:
            android.util.Log.d(TAG,"Error code for error that occurs when invalid activation code is provided."); break;
        case PowerAuthErrorCodes.BIOMETRY_CANCEL:
            android.util.Log.d(TAG,"Error code for Biometry action cancel error"); break;
        case PowerAuthErrorCodes.BIOMETRY_NOT_SUPPORTED:
            android.util.Log.d(TAG,"The device or operating system doesn't support biometric authentication."); break;
        case PowerAuthErrorCodes.BIOMETRY_NOT_AVAILABLE:
            android.util.Log.d(TAG,"The biometric authentication is temporarily unavailable."); break;
        case PowerAuthErrorCodes.BIOMETRY_NOT_RECOGNIZED:
            android.util.Log.d(TAG,"The biometric authentication did not recognize the biometric image (fingerprint, face, etc...)"); break;
        case PowerAuthErrorCodes.BIOMETRY_LOCKOUT:
            android.util.Log.d(TAG,"The biometric authentication is locked out due to too many failed attempts."); break;
        case PowerAuthErrorCodes.OPERATION_CANCELED:
            android.util.Log.d(TAG,"Error code for cancelled operations"); break;
        case PowerAuthErrorCodes.ENCRYPTION_ERROR:
            android.util.Log.d(TAG,"Error code for errors related to end-to-end encryption"); break;
        case PowerAuthErrorCodes.INVALID_TOKEN:
            android.util.Log.d(TAG,"Error code for errors related to token based auth."); break;
        case PowerAuthErrorCodes.PROTOCOL_UPGRADE:
            android.util.Log.d(TAG,"Error code for error that occurs when protocol upgrade fails at unrecoverable error."); break;
        case PowerAuthErrorCodes.PENDING_PROTOCOL_UPGRADE:
            android.util.Log.d(TAG,"The operation is temporarily unavailable, due to pending protocol upgrade."); break;
        case PowerAuthErrorCodes.TIME_SYNCHRONIZATION:
            android.util.Log.d(TAG,"Failed to synchronize time with the server."); break;
    }
} else if (t instanceof ErrorResponseApiException) {
    ErrorResponseApiException exception = (ErrorResponseApiException) t;
    Error errorResponse = exception.getErrorResponse();
    int httpResponseStatusCode = exception.getResponseCode();
    // Additional, optional objects assigned to the exception.
    JsonObject jsonResponseObject = exception.getResponseJson();
    String responseBodyString = exception.getResponseBody();
} else if (t instanceof FailedApiException) {
    FailedApiException exception = (FailedApiException) t;
    int httpStatusCode = exception.getResponseCode();
    // Additional, optional objects assigned to the exception.
    JsonObject jsonResponseObject = exception.getResponseJson();
    String responseBodyString = exception.getResponseBody();
}
```
<!-- end -->

Note that you typically don't need to handle all error codes reported in the `PowerAuthErrorException`, or report all that situations to the user. Most of the codes are informational and help the developers properly integrate SDK into the application. A good example is `INVALID_ACTIVATION_STATE`, which typically means that your application's logic is broken and you're using PowerAuthSDK in an unexpected way.

Here's the list of important error codes, which the application should properly handle:

- `BIOMETRY_CANCEL` is reported when the user cancels the biometric authentication dialog
- `PROTOCOL_UPGRADE` is reported when SDK failed to upgrade itself to a newer protocol version. The code may be reported from `PowerAuthSDK.fetchActivationStatusWithCallback()`. This is an unrecoverable error resulting in the broken activation on the device, so the best situation is to inform user about the situation and remove the activation locally.
- `PENDING_PROTOCOL_UPGRADE` is reported when the requested SDK operation cannot be completed due to a pending PowerAuth protocol upgrade. You can retry the operation later. The code is typically reported in the situations when SDK is performing protocol upgrade on the background (as a part of activation status fetch), and the application want's to calculate PowerAuth signature in parallel operation. Such kind of concurrency is forbidden since SDK version `1.0.0`


### Working with Invalid SSL Certificates

Sometimes, you may need to develop or test your application against a service that runs over HTTPS protocol with an invalid (self-signed) SSL certificate. By default, the HTTP client used in PowerAuth SDK communication validates the certificate. To disable the certificate validation, use a `PowerAuthSDK` initializer with a custom client configuration to initialize your PowerAuth SDK instance, like so:

<!-- begin codetabs Kotlin Java -->
```kotlin
// Set `HttpClientSslNoValidationStrategy as the defauld client SSL certificate validation strategy
val clientConfiguration = PowerAuthClientConfiguration.Builder()
    .clientValidationStrategy(HttpClientSslNoValidationStrategy())
    .build()
```
```java
// Set `HttpClientSslNoValidationStrategy as the defauld client SSL certificate validation strategy
final PowerAuthClientConfiguration clientConfiguration = new PowerAuthClientConfiguration.Builder()
                .clientValidationStrategy(new HttpClientSslNoValidationStrategy())
                .build();
```
<!-- end -->

Be aware, that using this option will lead to use an unsafe implementation of `HostnameVerifier` and `X509TrustManager` SSL client validation. This is useful for debug/testing purposes only, e.g. when untrusted self-signed SSL certificate is used on server side.

It's strictly recommended to use this option only in debug flavours of your application. Deploying to production may cause "Security alert" in Google Developer Console. Please see [this](https://support.google.com/faqs/answer/7188426) and [this](https://support.google.com/faqs/answer/6346016) Google Help Center articles for more details. Beginning 1 March 2017, Google Play will block publishing of any new apps or updates that use such unsafe implementation of `HostnameVerifier`.

How to solve this problem for debug/production flavours in the Gradle build script:

1. Define boolean type `buildConfigField` in the flavour configuration.
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

2. In code use this conditional initialization for `PowerAuthClientConfiguration.Builder` builder.
   <!-- begin codetabs Kotlin Java -->
   ```kotlin
   val clientBuilder = PowerAuthClientConfiguration.Builder()
   if (BuildConfig.TRUST_ALL_SSL_HOSTS) {
       clientBuilder.clientValidationStrategy(HttpClientSslNoValidationStrategy())
   }
   ```
   ```java
   PowerAuthClientConfiguration.Builder clientBuilder = new PowerAuthClientConfiguration.Builder();
   if (BuildConfig.TRUST_ALL_SSL_HOSTS) {
       clientBuilder.clientValidationStrategy(new HttpClientSslNoValidationStrategy());
   }
   ```
   <!-- end -->

3. Set `minifyEnabled` to true for release buildType to enable code shrinking with ProGuard.


### Debugging

The debug log is by default turned off. To turn it on, use the following code:

<!-- begin codetabs Kotlin Java -->
```kotlin
PowerAuthLog.setEnabled(true)
```
```java
PowerAuthLog.setEnabled(true);
```
<!-- end -->

To turn-on even more detailed log, use the following code:

<!-- begin codetabs Kotlin Java -->
```kotlin
PowerAuthLog.setVerbose(true)
```
```java
PowerAuthLog.setVerbose(true);
```
<!-- end -->

Note that it's highly recommended to turn-on this feature only for `DEBUG` build of your application. For example:

<!-- begin codetabs Kotlin Java -->
```kotlin
if (BuildConfig.DEBUG) {
    PowerAuthLog.setEnabled(true)
}
```
```java
if (BuildConfig.DEBUG) {
    PowerAuthLog.setEnabled(true);
}
```
<!-- end -->

## Additional Features

PowerAuth SDK for Android contains multiple additional features that are useful for mobile apps.

### Personal Information About User

If supported by the server, the PowerAuth mobile SDK can provide detailed information about the person associated with an activation. This information can be obtained either during the activation process or at a later time.

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
| `isEmailVerified`       | `Bool`   | True if the user's email address has been verified, else false<sup>1</sup> |
| `phoneNumber`           | `String` | The user's preferred telephone number<sup>2</sup> |
| `isPhoneNumberVerified` | `Bool`   | True if the user's telephone number has been verified, else false<sup>1</sup> |
| `gender`                | `String` | The user's gender |
| `birthdate`             | `Date`   | The user's birthday |
| `zoneInfo`              | `String` | The user's time zone, e.g. `Europe/Paris` or `America/Los_Angeles` |
| `locale`                | `String` | The end-user's locale, represented as a BCP47 language tag<sup>3</sup> |
| `address`               | `UserAddress` | The user's preferred postal address |
| `updatedAt`             | `Date`   | The time the user's information was last updated |
| `allClaims`             | `Map<String, Any>` | The full collection of standard claims received from the server |

If the `address` is provided, then `UserAddress` contains the following properties:

| Property                | Type     | Description |
|-------------------------|----------|-------------|
| `formatted`             | `String` | The full mailing address, with multiple lines if necessary |
| `street`                | `String` | The street address component, which may include house number, street name, post office box, and other multi-line information |
| `locality`              | `String` | City or locality component |
| `region`                | `String` | State, province, prefecture or region component |
| `postalCode`            | `String` | Zip code or postal code component |
| `country`               | `String` | Country name component |
| `allClaims`             | `Map<String, Any>` | Full collection of standard claims received from the server |

> Notes:
> 1. Value is false also when claim is not present in `allClaims` dictionary
> 2. Phone number is typically in E.164 format, for example `+1 (425) 555-1212` or `+56 (2) 687 2400`
> 3. This is typically an ISO 639-1 Alpha-2 language code in lowercase and an ISO 3166-1 Alpha-2 country code in uppercase, separated by a dash. For example, `en-US` or `fr-CA`

<!-- begin box info -->
Be aware that all properties in `UserInfo` and `UserAddress` objects are optional and the availability of information depends on actual implementation on the server.
<!-- end -->


### Password Strength Indicator

Choosing a weak passphrase in applications with high-security demands can be potentially dangerous. You can use our [Wultra Passphrase Meter](https://github.com/wultra/passphrase-meter) library to estimate the strength of the passphrase and warn the user when he tries to use such a passphrase in your application.

### Debug Build Detection

It is sometimes useful to switch PowerAuth SDK to a DEBUG build configuration to get more logs from the library. The DEBUG build is usually helpful during the application development, but on the other hand, it's highly unwanted in production applications. For this purpose, the `PowerAuthSDK.hasDebugFeatures()` method provides information whether the PowerAuth JNI library was compiled in DEBUG configuration. It is a good practice to check this flag and crash the process when the production application is linked against the DEBUG PowerAuth:

<!-- begin codetabs Kotlin Java -->
```kotlin
if (!BuildConfig.DEBUG) {
    // You can also check your production build configuration
    if (powerAuthSDK.hasDebugFeatures()) {
        throw RuntimeException("Production app with DEBUG PowerAuth")
    }
}
```
```java
if (!BuildConfig.DEBUG) {
    // You can also check your production build configuration
    if (powerAuthSDK.hasDebugFeatures()) {
        throw new RuntimeException("Production app with DEBUG PowerAuth");
    }
}
```
<!-- end -->

### Request Interceptors

The `PowerAuthClientConfiguration` can contain multiple request interceptor objects, allowing you to adjust all HTTP requests created by SDK, before execution. Currently, you can use the following two classes:

- `BasicHttpAuthenticationRequestInterceptor` to add basic HTTP authentication header to all requests
- `CustomHeaderRequestInterceptor` to add a custom HTTP header to all requests

For example:

<!-- begin codetabs Kotlin Java -->
```kotlin
val clientConfiguration = PowerAuthClientConfiguration.Builder()
    .requestInterceptor(BasicHttpAuthenticationRequestInterceptor("gateway-user", "gateway-password"))
    .requestInterceptor(CustomHeaderRequestInterceptor("X-CustomHeader", "123456"))
    .build()
```
```java
final PowerAuthClientConfiguration clientConfiguration = new PowerAuthClientConfiguration.Builder()
            .requestInterceptor(new BasicHttpAuthenticationRequestInterceptor("gateway-user", "gateway-password"))
            .requestInterceptor(new CustomHeaderRequestInterceptor("X-CustomHeader", "123456"))
            .build();
```
<!-- end -->

We don't recommend implementing the `HttpRequestInterceptor` interface on your own. The interface allows you to tweak the requests created in the `PowerAuthSDK` but also gives you an opportunity to break things. So, rather than create your own interceptor, try to contact us and describe what's your problem with the networking in the PowerAuth SDK. Also, keep in mind that the interface may change in the future. We can guarantee the API stability of public classes implementing this interface, but not the stability of the interface itself.

### Custom User-Agent

The `PowerAuthClientConfiguration` contains `userAgent` property that allows you to set a custom value for "User-Agent" HTTP request header for all requests initiated by the library:

<!-- begin codetabs Kotlin Java -->
```kotlin
val clientConfiguration = PowerAuthClientConfiguration.Builder()
    .userAgent("MyApp/1.0.0")
    .build()
```
```java
final PowerAuthClientConfiguration clientConfiguration = new PowerAuthClientConfiguration.Builder()
                .userAgent("MyApp/1.0.0")
                .build();
```
<!-- end -->

The default value of the property is composed as "APP-PACKAGE/APP-PACKAGE-VERSION PowerAuth2/PA-VERSION (OS/OS-VERSION, DEVICE-INFO)", for example: "com.test.app/1.0 PowerAuth2/1.7.0 (Android 11.0.0, SM-A525F)".

If you set `""` (empty string) to the `userAgent` property, then the default "User-Agent" provided by the operating system will be used. 
