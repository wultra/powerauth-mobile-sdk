# Migration from 1.1.x to 1.2.x

This guide contains instructions for migration from PowerAuth Mobile SDK version `1.1.x` to version `1.2.x`.

## Introduction

PowerAuth Mobile SDK in version `1.2.0` introduces following important changes: 

- **Android:** Complete reworked support for biometric authentication.
- **iOS & Android:** Removes classes related to password strength testing (`PasswordUtil` and `PA2PasswordUtil`)

### Compatibility with PowerAuth Server

- This release is fully compatible with PowerAuth Server version `0.22.x`.
- If your application doesn't use Recovery Codes, then you can use this SDK also against `0.21.x` servers.

## Android

### API changes

- Removed deprecated `PasswordUtil`, 
  - We recommend you to use our [Passphrase Meter](https://github.com/wultra/passphrase-meter) library as a replacement.
  - The removed interface is still available in [0.20.x branch](https://github.com/wultra/powerauth-mobile-sdk/tree/release/0.20.x/proj-android/PowerAuthLibrary/src/main/java/io/getlime/security/powerauth/util/password), so you can copy that files directly into your project.

- Removed ALL classes from package `io.getlime.security.powerauth.keychain.fingerprint`
  - All biometry related classes are now located in package `io.getlime.security.powerauth.biometry`

- New biometric authentication implementation now uses different system interfaces, depending on the system version:
  - `FingerprintManager` is used on Android 6.0, up to 8.1. In this case, our SDK displays a legacy fingerprint dialog (see [Behavioral Changes](#behavioral-changes))
  - `BiometricPrompt` is used on Android 9.0 and higher
  - On Android 9+, the fingerprint authentication configured in the previous version of SDK works properly with using new `BiometricPrompt`.

- `ICommitActivationWithFingerprintListener` is now `ICommitActivationWithBiometryListener` with following changes:
  - `void onFingerprintDialogCancelled()` is now `void onBiometricDialogCancelled()`
  - `void onFingerprintDialogSuccess()` is now `void onBiometricDialogSuccess()`
  - `void onFingerprintDialogFailed(PowerAuthErrorException error)` is now `void onBiometricDialogFailed(PowerAuthErrorException error)`
  
- `IFingerprintActionHandler` is now `IBiometricAuthenticationCallback` with following changes:
  - `void onFingerprintDialogCancelled()` is now `void onBiometricDialogCancelled(boolean userCancel)`
  - `void onFingerprintDialogSuccess(@Nullable byte[] biometricKeyEncrypted)` is now `void onBiometricDialogSuccess(@NonNull byte[] biometricKeyEncrypted)`
  - `void onFingerprintInfoDialogClosed()` is no longer available. You have to implement new `void onBiometricDialogFailed(@NonNull PowerAuthErrorException error)`
  
- In `PowerAuthSDK`, following biometry related interfaces were changed:
  - Commit activation 
    - `void commitActivation(..., final ICommitActivationWithFingerprintListener callback)` 
    - is now `ICancelable commitActivation(..., final ICommitActivationWithBiometryListener callback)`
  - Authenticate method 
    - `void authenticateUsingFingerprint(..., final IFingerprintActionHandler callback)` 
    - is now `ICancelable authenticateUsingBiometry(..., final IBiometricAuthenticationCallback callback)`

- We slightly changed string resources bundled in the SDK:
  - String `fingerprint_dialog_icon_description` is now `accessibility_icon_fingerprint`
  - On top of that, we have added a couple of new localized strings.

- You can now customize legacy fingerprint authentication dialog with using `BiometricDialogResources` class. Check [source code](../proj-android/PowerAuthLibrary/src/main/java/io/getlime/security/powerauth/biometry/BiometricDialogResources.java#L29) of that class, for more details.

- You can use `BiometricAuthentication` class to test, whether device supports biometry and whether biometric authentication is enrolled on the system.
  - Call `BiometricAuthentication.isBiometricAuthenticationAvailable(context)` to test general support.
  - Call `BiometricAuthentication.canAuthenticate(context)` to get more detailed status (please also see [known bugs](#known-bugs) section below)
  
- `PowerAuthErrorException` can contain following new constants: `PA2ErrorCodeBiometryNotSupported`, `PA2ErrorCodeBiometryNotAvailable`, `PA2ErrorCodeBiometryNotRecognized`

- Added a new activation state `ActivationStatus.State_Deadlock`.
  - Note that this state cannot be achieved in this version of SDK. The constant is defined and reserved for the future version `1.3.0`. The full explanation why we introduced deadlock is explained in [issue #247](https://github.com/wultra/powerauth-mobile-sdk/issues/247).

### Behavioral changes

- If legacy fingerprint dialog displays an error, then it's automatically closed after a short time. The `BiometricPrompt` does the same thing, so we wanted to achieve similar behavior.
- Our legacy fingerprint dialog now reports status changes to an accessibility manager. 
- We're now handling biometric authentication cancelation events from the system. For example, if user locks down the device during  authentication, then our SDK report cancel back to the application. 
- Due to bug in Android 9 `BiometricPrompt` (see [known bugs](#known-bugs)), we recommend you to DISABLE critical UI elements in your application (like button for authentication) during the time between the authenticate call and the callback from SDK. The reason for that is that you probably don't want to allow user to authenticate for more than once.
- In case that biometry is temporarily, or permanently locked down, then the SDK will use this information to simulate a failed authentication attempt against the server. The purpose of this is to increase a number of failed attempts on the server and limit the attacker's ability to trick the biometric sensor.
 

### Known bugs

The biometric support on Android platform is kind of mess right now (August 2019). We have discovered following problems during the testing of SDK:

- Android 9.0 version of `BiometricPrompt` contains a very nasty bug that delays the error callback to the application, when error is detected immediately. For example, if the biometric sensor is locked down (due to too many failed attempts), then this situation is reported after 2 seconds long delay. Unfortunately, no biometric system UI is displayed during this time period, so we recommend you to guarantee, that user cannot interact with the screen, during this period. For more details, [check our implementation](../proj-android/PowerAuthLibrary/src/main/java/io/getlime/security/powerauth/biometry/impl/BiometricAuthenticator.java#L298).

- On Android 9, there's no new interface to tell your application that there's enrolled biometry on the device. This will be fixed in Android 10, which introduces [BiometricManager](https://developer.android.com/reference/android/hardware/biometrics/BiometricManager). Until then, we have to believe, that old, deprecated `FingerprintManager` works properly.

- Face detection doesn't work on some Samsung devices. This is known issue and we cannot workaround it.

- Some devices doesn't provide an error message when biometric authentication fails. We're fixing this in our SDK by using a generic message.


## iOS

### API changes

- Removed deprecated `PA2PasswordUtil`
  - We recommend you to use our [Passphrase Meter](https://github.com/wultra/passphrase-meter) library as a replacement.
  - The removed interface is still available in [0.20.x branch](https://github.com/wultra/powerauth-mobile-sdk/tree/release/0.20.x/proj-xcode/Classes/util), so you can copy that files directly into your project.
- Added a new activation state `PA2ActivationState_Deadlock`
  - This may produce a swift warning that `switch must be exhaustive` and `note: add missing case: '.deadlock'`. You can ignore this warning or add a similar processing than you already have for `.removed` state.
  - Note that this state cannot be achieved in this version of SDK. The constant is defined and reserved for the future version `1.3.0`. The full explanation why we introduced deadlock is explained in [issue #247](https://github.com/wultra/powerauth-mobile-sdk/issues/247).
