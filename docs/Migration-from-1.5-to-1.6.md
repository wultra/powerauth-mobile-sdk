# Migration from 1.5.x to 1.6.x

This guide contains instructions for migration from PowerAuth Mobile SDK version `1.5.x` to version `1.6.x`.

## Introduction

TODO...

### Compatibility with PowerAuth Server

- This release is fully compatible with PowerAuth Server version `0.24.x`, `1.0.x` and `1.1.x`.

## Android

### API changes

- PowerAuth mobile SDK now uses libraries from `androidx` namespace as a replacement for old support library. If your application is still using the support library, then we highly recommend you to [migrate your code to AndroidX](https://developer.android.com/jetpack/androidx/migrate).
- PowerAuth mobile SDK now uses `androidx.biometry` for a biometric authentication, so you can upgrade this support library independently to PowerAuth mobile SDK. This is useful in case your users encounter a various device specific incompatibilities.
- All biometry-related API calls no longer accept `FragmentManager` as a parameter. You can now choose between variants with `Fragment` or `FragmentActivity` at input:
  - `PowerAuthSDK.commitActivation(Context, Fragment, String, String, String, ICommitActivationWithBiometryListener)`
  - `PowerAuthSDK.commitActivation(Context, FragmentActivity, String, String, String, ICommitActivationWithBiometryListener)`
  - `PowerAuthSDK.addBiometryFactor(Context, Fragment, String, String, String, IAddBiometryFactorListener)`
  - `PowerAuthSDK.addBiometryFactor(Context, FragmentActivity, String, String, String, IAddBiometryFactorListener)`
  - `PowerAuthSDK.authenticateUsingBiometry(Context, Fragment, String, String, IBiometricAuthenticationCallback)`
  - `PowerAuthSDK.authenticateUsingBiometry(Context, FragmentActivity, String, String, IBiometricAuthenticationCallback)`
- The `BiometricDialogResources` class containing resource IDs for the biometric authentication has been heavily reduced. Please review the actual usage of the resources carefuly.
  - The `BiometricDialogResources.Strings` section has been reduced. The old section constructor is now deprecated and you can review what strings are still in use.
  - The `BiometricDialogResources.Drawables` section has been reduced. The old section constructor is now deprecated and you can review what images are still in use. 
  - There's no longer `BiometricDialogResources.Colors` section. 
  - There's no longer `BiometricDialogResources.Layout` section.
  

## iOS

### API changes

- TODO...
