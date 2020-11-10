# Migration from 1.4.x to 1.5.x

This guide contains instructions for migration from PowerAuth Mobile SDK version `1.4.x` to version `1.5.x`.

## Introduction

PowerAuth Mobile SDK in version `1.5.0` is a maintenance release that brings few enhancements to Android and adds support for more Apple platforms.

### Compatibility with PowerAuth Server

- This release is fully compatible with PowerAuth Server version `0.24.x` and `1.0.x`.

## Android

### API changes

- The `IBiometricAuthenticationCallback` interface has slightly changed:
  - `void onBiometricDialogSuccess(@NonNull byte[] biometricKeyEncrypted)` is now `void onBiometricDialogSuccess(@NonNull BiometricKeyData biometricKeyData)`.
  - You can call `biometricKeyData.getDerivedData()` to get data equivalent to previous `byte[] biometricKeyEncrypted`.
  
- The `IAddBiometryFactorListener` interface is now in `io.getlime.security.powerauth.biometry` package.
  - `onAddBiometryFactorFailed(@NonNull PowerAuthErrorException error)` callback now returns `PowerAuthErrorException` instead of `Throwable`. 

- The `ICommitActivationWithBiometryListener` interface now provides non-null exception in `onBiometricDialogFailed(@NonNull PowerAuthErrorException exception)` callback.

- `PowerAuthKeychainConfiguration.Builder` has new option `authenticateOnBiometricKeySetup(boolean)` to tell SDK that biometric authentication is not required for the biometric key setup.
  - Altering this option to `false` will cause that RSA keypair is created in Android KeyStore instead of AES key.
  - Previously created AES keys are not altered, so biometric factors configured with older SDKs works as before.

## iOS

### API changes

- Minimum supported iOS version is now `9.0`

- PowerAuth mobile SDK is now available for `tvOS` and `macCatalyst` platform and fully supports Apple Silicon CPU architectures.

- Support for new platforms has the following implications to SDK integration:
  - CocoaPods tool version `1.10+` is required.
  - CocoaPods integration now uses precompiled `XCFrameworks` as binary artifacts, so be careful in case that your application project has whole `Pods` folder added to the git source control. 
