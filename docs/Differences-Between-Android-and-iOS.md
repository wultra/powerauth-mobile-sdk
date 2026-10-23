# Differences Between Android and iOS

PowerAuth Mobile SDK implements the same protocol and offers the same set of features on both Android and iOS. However, the platforms provide very different security facilities. Android uses `Android KeyStore` and `BiometricPrompt`, while iOS uses `Keychain` and the `LocalAuthentication` framework. As a result, the SDK behaves differently in some situations, and some defaults differ between platforms.

This document is intended for teams that develop the same application for both platforms, or that build a cross-platform wrapper on top of the native SDKs. It does not describe API differences. Instead, it focuses on differences in concepts, default behavior, and usage that may lead to inconsistent user experience if you are not aware of them. For API details, follow the links to the platform-specific documentation.

## Table of Contents

- [Summary](#summary)
- [Biometry](#biometry)
- [Protocol Upgrade](#protocol-upgrade)
- [Error Handling](#error-handling)
- [Activation Data Storage](#activation-data-storage)
- [Platform-Specific Features](#platform-specific-features)
- [SDK Setup, Lifecycle, and Threading](#sdk-setup-lifecycle-and-threading)

## Summary

| Topic | Android | iOS |
|-------|---------|-----|
| Biometric key after a fingerprint or face is added or removed | **Invalidated** by default | **Preserved** by default |
| Biometric authentication when enabling biometry | Required by default | Not required |
| Obtaining biometric authentication | Always asynchronous, requires a fragment or an activity | Can be done implicitly, but blocks the calling thread |
| Biometric lockout in status | Not reported until authentication is attempted | Reported as `.lockout` |
| Biometric error dialog | Displayed by the SDK by default | Not displayed, the system UI only |
| Fallback to the device passcode | Not available | Optional, disabled by default |
| Facial biometry | Only on devices with a `BIOMETRIC_STRONG` sensor | Face ID / Touch ID |
| Biometry factor during protocol upgrade | **Removed** by default | Preserved automatically |
| Error representation | Three exception classes | Single `NSError` with an error code |
| User cancel of biometric dialog | Typically a dedicated cancel callback | `.biometryCancel` error code |
| Activation data after app reinstall | Removed together with the application | Survives in Keychain, but the SDK removes it on first launch |
| Activation data protection level | Depends on the device, can be enforced | Always Keychain |
| Data sharing between applications | Not available | Available via Keychain sharing and App Groups |
| Wearable support | Not available | Apple Watch |

## Biometry

Biometry is the area with the most significant differences between the platforms. In both cases, the SDK protects a biometry factor-related key with the platform's secure storage, and the key is released only after the user successfully authenticates with biometry. The way the key is protected determines most of the differences described below.

- **Android** protects the key with a key stored in Android KeyStore that requires user authentication. The authentication is performed with `androidx.biometric.BiometricPrompt` that unlocks the KeyStore key for a single cryptographic operation.
- **iOS** stores the key as a Keychain item protected with an access control flag. The system displays the Touch ID or Face ID prompt automatically when the item is accessed.

### Biometric Enrollment Change

The most important difference is how the SDK behaves when the user changes the biometry enrolled in the system. For example, when the user adds a new fingerprint, removes an existing one, or re-enrolls Face ID.

| | Android | iOS |
|---|---------|-----|
| Default behavior | The biometric key is invalidated | The biometric key is preserved |
| Configuration | `PowerAuthBiometricConfiguration.Builder().invalidateBiometricFactorAfterChange()` | `PowerAuthBiometricConfiguration.invalidateBiometricFactorAfterChange` |
| Default value | `true` | `false` |

On **Android**, the KeyStore key is permanently invalidated by the system once the enrollment changes. The next attempt to use biometric authentication fails with `BIOMETRY_NOT_AVAILABLE`, the SDK removes the invalidated key and, unless you [disabled the error dialog](android/Biometric-Authentication-Setup.md#disable-error-dialog-after-failed-biometry), displays a "Fingerprint Disabled" dialog to the user. The user then has to set up biometric authentication again.

On **iOS**, the Keychain item remains accessible with the new biometry by default. If you set `invalidateBiometricFactorAfterChange` to `true`, the item becomes inaccessible after the change and the biometric operation fails.

If you want consistent behavior on both platforms, set the option explicitly on both of them. Keep in mind that:

- The option is applied only when a new biometric key is created. To apply the change to an existing activation, [remove](android/Biometric-Authentication-Setup.md#disable-biometric-authentication) and [add](android/Biometric-Authentication-Setup.md#enable-biometric-authentication) the biometry factor again.
- Invalidating the key after enrollment change is the more secure option. Anyone who knows the device passcode can enroll their own fingerprint or face, and then authenticate in your application on the user's behalf.

For more details, see [Biometry Factor-Related Key Lifetime](android/Biometric-Authentication-Setup.md#biometry-factor-related-key-lifetime) for Android and [Biometry Factor-Related Key Lifetime](ios/Biometry-Setup.md#biometry-factor-related-key-lifetime) for iOS.

### Enabling Biometry

When the biometry factor is enabled, either during the activation persist or later with `addBiometryFactor()`:

- **Android** asks the user to authenticate with biometry by default. That's because the default KeyStore key requires authentication also for the encryption. You must therefore provide a `PowerAuthBiometricPrompt` with a fragment or an activity. You can turn this behavior off by setting `authenticateOnBiometricKeySetup` to `false` in `PowerAuthBiometricConfiguration`. In that case, the SDK uses an asymmetric key pair instead, and the setup requires no user interaction. Be aware that the key-pair generation may take noticeable time on older devices.
- **iOS** never asks for biometric authentication when the biometry factor is enabled. The Keychain item can be created without the user's interaction.

As a result, enabling biometry on Android may be canceled by the user, or may fail due to a biometry error, while on iOS it requires the user's knowledge factor only.

### Obtaining Biometric Authentication

- **Android** always obtains the biometry factor-related key asynchronously, with `authenticateUsingBiometrics()`. The function displays `BiometricPrompt` and returns a `PowerAuthAuthentication` object in the callback. You cannot create an authentication object with biometry without such a call.
- **iOS** allows you to create `PowerAuthAuthentication.possessionWithBiometry()` and pass it directly to an SDK function. In this case, the biometric prompt is displayed when the SDK accesses the Keychain, and the calling thread is blocked until the user finishes the authentication. To avoid blocking the main thread, obtain the authentication object in advance with `authenticateUsingBiometry()`. See [Thread-blocking operation](ios/Biometry-Troubleshooting.md#thread-blocking-operation) for more details.

<!-- begin box warning -->
On Android, the SDK finishes the cryptographic work on a background thread after the system biometric prompt is dismissed. Disable the interactive UI elements until the callback is called. See [Fetching the Biometry Factor-Related Key for Authentication](android/Biometric-Authentication-Setup.md#fetching-the-biometry-factor-related-key-for-authentication) for more details.
<!-- end -->

### Biometric Status and Lockout

Both platforms provide `PowerAuthBiometricStatus` with system availability, biometry type, and activation availability. There are the following differences:

- **iOS** reports `.lockout` system status when the biometry is locked out due to too many failed attempts.
- **Android** doesn't report the lockout in the status. You will learn about the lockout only after you attempt to authenticate.
- **Android** may report `BiometryType.GENERIC` when the device supports more than one type of biometry, or when the exact type cannot be determined. Your UI should use generic terms, such as "biometry", in such case. **iOS** always reports either Touch ID or Face ID.

Both platforms share the same protective behavior when the user fails biometric authentication too many times in a row. The SDK pretends that the authentication succeeded and provides an invalid biometry factor-related key. This leads to failed authentication on the server and an increased counter of failed attempts, which limits the number of attempts available to an attacker. On Android, this applies only when the user fails in the currently displayed prompt. If the biometry is already locked out before the prompt is displayed, then the SDK reports the `BIOMETRY_LOCKOUT` error.

### Biometric Error Dialog

- **Android** displays its own error dialog after a failed biometric authentication by default. For example, when the biometric key was invalidated, or the biometry is locked out. You can [customize the dialog resources](android/Biometric-Authentication-Setup.md#customize-biometric-dialog-resources), or [disable the dialog](android/Biometric-Authentication-Setup.md#disable-error-dialog-after-failed-biometry) and present the error on your own with help of `BiometricErrorInfo`.
- **iOS** doesn't display any additional UI. Only the system Touch ID or Face ID prompt is displayed, and errors are reported to the application.

### Platform-Specific Biometric Options

The following options exist only on one of the platforms:

| Option | Platform | Description |
|--------|----------|-------------|
| `allowFallbackToDevicePasscode` | iOS | Allows the user to unlock the biometric key with the device passcode. Disabled by default. Once enabled, `invalidateBiometricFactorAfterChange` has no effect. Not recommended for applications that fall under EU banking regulations, because the factor is no longer purely biometric. |
| Custom `LAContext` | iOS | Allows you to customize the system dialog, or pre-authorize the context. The SDK invalidates the context after use by default (`invalidateLocalAuthenticationContextAfterUse`). |
| `confirmBiometricAuthentication` | Android | Asks the user for an additional confirmation after successful authentication on Android 10+. Disabled by default. |
| `authenticateOnBiometricKeySetup` | Android | See [Enabling Biometry](#enabling-biometry). |

There are also differences caused by the platforms themselves:

- **Android** supports facial biometry only on devices with a `BIOMETRIC_STRONG` (class 3) sensor, because the key must be protected in Android KeyStore. On other devices, face unlock cannot be used for PowerAuth biometric authentication. See [Facial Biometrics on Android](android/Biometric-Authentication-Setup.md#facial-biometrics-on-android).
- **iOS** devices with Face ID fail to authenticate when you request another biometric authentication too soon after a previous successful one. See [Parallel biometric authentications](ios/Biometry-Troubleshooting.md#parallel-biometric-authentications).
- **tvOS** doesn't support biometry at all.

## Protocol Upgrade

The [authenticated protocol upgrade](Upgrading-to-Post-Quantum-Cryptography.md) migrates an existing activation to a newer algorithm. On both platforms, the upgrade must be authenticated with the knowledge factor. The difference is in how the biometry factor is handled, because the upgrade replaces the biometry factor-related key with a new one.

- **iOS** preserves the biometry factor automatically. The SDK replaces the Keychain item without displaying the biometric prompt, so there's only one variant of `startProtocolUpgrade()` you need to call. An optional variant with `customBiometryKek` exists for applications that provide their own biometric key.
- **Android** needs to protect the new key with Android KeyStore, which may require biometric authentication. That's why there are three variants of `startProtocolUpgrade()`:
  - Without a biometric prompt: the biometry factor is **removed** during the upgrade.
  - With `PowerAuthBiometricPrompt`: the biometry factor is upgraded. This variant requires `authenticateOnBiometricKeySetup` to be set to `false`, otherwise it fails with `WRONG_PARAMETER`.
  - With `SecureData`: intended for applications that use an external biometric key.

Because `authenticateOnBiometricKeySetup` is enabled by default on Android, the biometry factor is removed during the upgrade unless you change the configuration. The Android `ProtocolUpgradeResult` therefore contains the additional `biometryFactorRemoved` flag. If it's set, offer the user to enable biometry again once the upgrade is completed. The iOS result has no such flag.

In all other aspects, the upgrade behaves the same on both platforms. That includes the `activationStatusFetchRequired` result flag, the pending upgrade state, and the rollback on failure.

For more details, see [Authenticated Protocol Upgrade](android/Authenticated-Protocol-Upgrade.md) for Android and [Authenticated Protocol Upgrade](ios/Authenticated-Protocol-Upgrade.md) for iOS.

## Error Handling

Both SDKs share the same failure reasons, but they report them differently.

### Error Representation

- **Android** uses three exception classes:
  - `PowerAuthErrorException` with an integer code from `PowerAuthErrorCodes` for SDK-related failures.
  - `ErrorResponseApiException` when the HTTP request fails and the server returns an error object.
  - `FailedApiException` when the HTTP request fails for any other reason.
- **iOS** uses a single `NSError` object. Errors from `PowerAuthErrorDomain` provide `PowerAuthErrorCode` via the `powerAuthErrorCode` property. For errors from other domains, the property returns `.NA`. Server failures are reported with the `.networkError` code, and the server's response, if available, is in the `powerAuthRestApiErrorResponse` property.

So, on Android, you have to determine the type of the exception first, while on iOS you always switch over the error code.

### Error Delivery

- **Android** reports errors of asynchronous operations to listener callbacks, and throws `PowerAuthErrorException` from synchronous functions.
- **iOS** reports errors of asynchronous operations to completion closures. Synchronous functions report errors via `NSError**` in Objective-C, which is converted to `throws` in Swift.

### Cancel of Biometric Authentication

- **Android** typically reports the user's cancel via a dedicated callback, such as `onBiometricDialogCancelled(userCancel)` or `onPersistActivationCancelled(userCancel)`. The `userCancel` parameter tells you whether the user or your application canceled the operation.
- **iOS** reports the cancel as an error with the `.biometryCancel` code. If the user taps the fallback button in the system dialog, then the `.biometryFallback` code is reported.

### Platform-Specific Error Codes

| Platform | Error codes |
|----------|-------------|
| Android | `BIOMETRY_NOT_SUPPORTED`, `BIOMETRY_NOT_ENROLLED`, `BIOMETRY_NOT_RECOGNIZED`, `BIOMETRY_LOCKOUT`, `INSUFFICIENT_KEYCHAIN_PROTECTION` |
| iOS | `.biometryFallback`, `.biometryFailed`, `.externalPendingOperation`, `.watchConnectivity` |

On Android, the biometry-related exceptions may also contain `BiometricErrorInfo` in the `additionalInformation` property. It tells you whether the application should present the error to the user.

For more details, see [Error Handling](android/Common-SDK-Tasks.md#error-handling) for Android and [Error Handling](ios/Common-SDK-Tasks.md#error-handling) for iOS.

## Activation Data Storage

### Application Reinstall

- **Android** stores activation data in the application's private storage, which is removed together with the application. After reinstall, the application starts with no activation.
- **iOS** stores activation data in Keychain, which is **not** removed when the application is uninstalled. To keep the behavior consistent with user expectations, the SDK stores a flag in `UserDefaults`, and removes all Keychain data on the first launch after reinstall. As a result, the application also starts with no activation.

If you use [activation data sharing](ios/Share-Activation-Data.md) on iOS, the flag must be stored in a shared App Group. Otherwise, the application and its extensions do not see the same flag. See [UserDefaults Migration](ios/Troubleshooting.md#userdefaults-migration) for more details.

### Activation Data Protection

- **Android** encrypts the activation data with a key generated by Android KeyStore. The level of protection depends on the device and may be `NONE`, `SOFTWARE`, `HARDWARE`, or `STRONGBOX`. You can enforce the minimal required level in `PowerAuthKeychainConfiguration`. If the device doesn't meet the requirement, the SDK construction fails with `INSUFFICIENT_KEYCHAIN_PROTECTION`, and your application should inform the user. StrongBox is disabled by default due to poor reliability and performance. See [Activation Data Protection](android/Configuration.md#activation-data-protection).
- **iOS** always stores the data in the system Keychain, so there's no protection level to choose or check.

## Platform-Specific Features

The following features are available on iOS only:

- [Share Activation Data](ios/Share-Activation-Data.md) – Share an activation between the application and its extensions, or between multiple applications from the same vendor. When data is shared, some operations, such as activation or protocol upgrade, can be performed by only one application at a time. Other applications receive the `.externalPendingOperation` error until the operation is finished.
- [Apple Watch Support](ios/Apple-Watch-Support.md) – Transfer the activation status and tokens to a paired Apple Watch.
- [tvOS Support](ios/Installation.md) – The SDK supports tvOS, except for biometry and watch connectivity.

There is no equivalent of these features on Android.

## SDK Setup, Lifecycle, and Threading

- **Context**: On Android, most SDK functions require an Android `Context` parameter, and biometric functions also require a fragment or an activity to display `BiometricPrompt`. On iOS, no such parameters are needed.
- **Application lifecycle**: On Android, the SDK registers for application lifecycle callbacks, which are used, for example, by the [synchronized time](android/Synchronized-Time.md) service. To make this work, build the `PowerAuthSDK` instance with the application context, or register `PowerAuthAppLifecycleListener` in your `Application.onCreate()`. See [SDK Configuration](android/Configuration.md). On iOS, no such step is needed.
- **Callback thread**: On both platforms, callbacks of asynchronous operations are called on the main thread.
- **Blocking calls**: On iOS, functions that use biometry implicitly block the calling thread while the biometric prompt is displayed. See [Obtaining Biometric Authentication](#obtaining-biometric-authentication). On Android, biometric authentication is always asynchronous.
- **Parallel biometric authentication**: Both platforms allow only one biometric authentication at a time. Another request issued while the prompt is displayed is canceled.
