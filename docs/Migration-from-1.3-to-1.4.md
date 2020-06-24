# Migration from 1.3.x to 1.4.x

This guide contains instructions for migration from PowerAuth Mobile SDK version `1.3.x` to version `1.4.x`.

## Introduction

PowerAuth Mobile SDK in version `1.4.0` introduces support for an [additional activation OTP](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Additional-Activation-OTP.md) feature.

### Compatibility with PowerAuth Server

- This release is fully compatible with PowerAuth Server version `0.24.x`.

### Important

- Please be aware that PowerAuth mobile SDK `1.4.1` fixed a [serious issue with protocol upgrade](https://github.com/wultra/powerauth-mobile-sdk/issues/302) from `V2.x` to `V3.1`. You should upgrade your application to `1.4.1` and newer. 

## Android

### API changes

- PowerAuth mobile SDK now requires at least Android API level 19 (Android 4.4 KitKat).

- Added a new `PowerAuthActivation` class that unifies an activation creation process. Use new simple `PowerAuthSDK.createActivation(activation, listener)` method to create an activation.
  - This change doesn't break your existing code. We still maintain an old way of the activation creation, but don't hesitate to try this new approach. 
  
- The `ActivationStatus.State_OTP_Used` enumeration is now deprecated. Please use `ActivationStatus.State_Pending_Commit` as a replacement.

- _Version 1.4.2+:_ The `PA2Keychain` class is no longer available. You can use `KeychainFactory` and `Keychain` interface from the same package as a replacement. Changes in the underlying keychain implementation has the following impact into your application's code:
  - `PowerAuthSDK.Builder.build()` method now throws an exception in case that your `PowerAuthKeychainConfiguration` enforces a higher level of keychain protection than it is supported on the device. By default, `KeychainProtection.NONE` is used, so the fallback to no-encryption is allowed and such exception is never thrown.
  - If you use higher levels of proteciton than `KeychainProtection.NONE`, then your application may use `KeychainFactory.getKeychainProtectionSupportedOnDevice()` to determine whether the device supports enough level of protection. You can display an error message to the user, if the application cannot be used on the device.

## iOS

### API changes

- PowerAuth mobile SDK now supports bitcode.

- Added a new `PowerAuthActivation` class that unifies an activation creation process. Use new simple `PowerAuthSDK.createActivation(activation) { .. } ` method to create an activation.
  - This change doesn't break your existing code. We still maintain an old way of the activation creation, but don't hesitate to try this new approach. 

- The following interfaces are now deprecated:
  - The `PA2ActivationState.otp_Used` enumeration is deprecated. Use `PA2ActivationState.pendingCommit` as a replacement.

- Removed deprecated interfaces:
  - The `PA2SupportedBiometricAuthentication` enumeration is no longer available. Use `PA2BiometricAuthenticationType` as a replacement.
  - The `PA2Keychain.addValue(Data, forKey: String, useBiometry: Bool)` method is no longer available. Use `addValue(Data, forKey: String, access: PA2KeychainItemAccess)` as a replacement.
  - The `PA2Keychain.addValue(Data, forKey: String, useBiometry: Bool, completion:)` method is no longer available. Use `addValue(Data, forKey: String, access: PA2KeychainItemAccess, completion:)` as a replacement.
