# Biometric Authentication Setup

PowerAuth SDK for Android provides an abstraction on top of the base Biometric Authentication support. While the authentication / data signing itself is handled using the `PowerAuthAuthentication` object used in [regular request signing](Android-Data-Signing.md), other biometry-related processes require their own API.

## Check Biometric Authentication Status

You have to check for Biometric Authentication on three levels:

- **System Availability**: If a biometric scanner is present on the system.
- **Activation Availability**: If biometry factor data are available for given activation.
- **Application Availability**: If the user decides to use biometric authentication for the given app. _(optional)_

PowerAuth SDK for Android provides code for the first and second of these checks.

### Overall status

To get information on whether biometric authentication is fully available, you can use the following code:

```kotlin
if (powerAuthSDK.isAuthenticationWithBiometricsAvailable(context)) {
    // Biometric authentication is available, you can construct PowerAuthAuthentication with biometry 
} else {
    // Fallback to PIN
}
```

The function returns `true` only if activation has biometry factor-related data available and the device has a biometric sensor available and biometrics are enrolled in the system.

<!-- begin box info -->
Note that this doesn't reflect state when the sensor is temporarily or permanently locked out. Such information is available only after you attempt to authenticate with biometrics.
<!-- end -->

To get more detailed information, use the following code:

```kotlin
val biometricStatus = powerAuthSDK.getBiometricStatus(context)
```

The next chapters explain in more detail the usage of the returned `PowerAuthBiometricStatus` object.

### System Availability

To check, whether the biometrics is available at the system level, use the following code:

```kotlin
// Get biometric status
val biometricStatus = powerAuthSDK.getBiometricStatus(context)
when (biometricStatus.systemStatus) {
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
when (biometricStatus.biometryType) {
    BiometryType.NONE ->
        print("Biometry is not supported on the system.")
    BiometryType.GENERIC ->
        // It's not possible to determine the exact type of biometry.
        // This occurs on Android 10+ systems when the device supports
        // more than one type of biometric authentication. In this case,
        // you should use generic terms in your UI, such as "Authenticate with biometry".
        // This issue can also arise on devices that support a new type of biometric
        // sensor, or on older malfunctioning devices that fail to declare 
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

### Activation Availability

To check whether activation is configured for authentication with biometrics, use the following code:

```kotlin
// Get biometric status
val biometricStatus = powerAuthSDK.getBiometricStatus(context)
// Determine overall availability
if (biometricStatus.isAuthenticationWithBiometricsAvailable) {
    // Equal to call:
    //   powerAuthSDK.isAuthenticationWithBiometricsAvailable(context)
}
// Determine whether local activation has biometric factor configured.
if (biometricStatus.isBiometricFactorConfigured) {
    // Equal to call
    //   powerAuthSDK.hasBiometryFactor(context)
}
```

### Application Availability

The last check is fully under your control. By keeping the biometric settings flag, for example, a `boolean` in `SharedPreferences`, you can show the user an expected biometric authentication status (in a disabled state, though) even in the case biometric authentication is not enabled or when no fingers are enrolled on the device.


## Enable Biometric Authentication

In case an activation does not yet have biometry-related factor data, and you would like to enable biometric authentication support, use the following code:

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

    override fun onAddBiometryFactorFailed(error: Throwable) {
        // Error occurred, report it to the user.

        // It's recommended to fetch activation's status to synchronize biometric factor
        // configuration with the server.
    }
})
```

By default, PowerAuth SDK asks the user to authenticate with the biometric sensor also during the setup procedure (or during the [activation persist](Android-Device-Activation.md#persisting-activation-data)). To alter this behavior, use the following code to change the `PowerAuthBiometricConfiguration` provided to the `PowerAuthSDK` instance:

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

## Disable Biometric Authentication

To remove biometry-related factor data used by biometric authentication use the following code:

```kotlin
powerAuthSDK.removeBiometryFactor(context, object: IRemoveBiometryFactorListener {
    override fun onRemoveBiometryFactorSucceed() {
        // Everything went OK, biometric authentication is ready to be used
    }

    override fun onRemoveBiometryFactorFailed(error: Throwable) {
        // Error occurred, report it to the user.

        // It's recommended to fetch activation's status to synchronize biometric factor
        // configuration with the server.
    }
})
```

## Fetching the Biometry Factor-Related Key for Authentication

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

## Facial Biometrics on Android

Currently, facial authentication only works with several Android device models. This is because to implement facial authentication securely, the PowerAuth SDK needs to protect the biometry-related key in the Android Keystore with a biometric sensor. This type of secure storage is only supported on devices with the `BIOMETRIC_STRONG (class 3)` sensor type, as explained in the official documentation:

- https://source.android.com/docs/security/features/biometric

The Android source codes contain a list of devices with strong biometry support.

- [biometric/biometric/src/main/res/values/devices.xml](https://cs.android.com/androidx/platform/frameworks/support/+/androidx-main:biometric/biometric/src/main/res/values/devices.xml;l=81)

## Biometry Factor-Related Key Lifetime

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

## Biometric Authentication Details

The `BiometricAuthentication` class is a high-level interface that provides interfaces related to biometric authentication for the SDK or for application purposes. The class hides all technical details, so it can be safely used also on systems that don't provide biometric interfaces, or if the system has no biometric sensor available. The implementation under the hood uses `androidx.biometric.BiometricPrompt` and `androidx.biometric.BiometricManager` classes.

### Customize Biometric Dialog Resources

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

### Disable Error Dialog After Failed Biometry

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

### Biometric Authentication Confirmation

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

## Read Next

- [Device Activation Removal](Android-Device-Activation-Removal.md)
