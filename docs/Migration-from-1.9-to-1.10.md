# Migration from 1.9.x to 1.10.x

PowerAuth Mobile SDK in version `1.10.0` provides the following improvements:

- PowerAuth mobile SDK no longer supports activation by the recovery code.
- New `PowerAuthBiometricConfiguration` class that simplifies biometric configuration of `PowerAuthSDK` class.
- PowerAuth mobile SDK now ensures sensitive keys are not retained in memory.

### Compatibility with PowerAuth Server

- This release is fully compatible with PowerAuth Server version `1.9.0` and newer.

## Android

Notable changes on Android:

- New `PowerAuthBiometricPrompt` class simplifies biometric key setup and authentication.
- Added the `SecureData` class to `io.getlime.security.powerauth.core` package to enhance in-memory management of sensitive data.

### API changes

- The following methods in `PowerAuthSDK` class are deprecated:
  - `changePasswordUnsafe()` - use asynchronous `changePassword()` as a replacement.
  - `persistActivationWithAuthentication()` - use asynchronous variant with `IPersistActivationListener` as a callback parameter.
  - `persistActivationWithPassword()` - use asynchronous variant with `IPersistActivationListener` as a callback parameter.
  - `persistActivation(..., IPersistActivationWithBiometricsListener)` - use asynchronous method with `IPersistActivationListener` as a callback parameter.

- The following methods in `PowerAuthKeychainConfiguration` are now deprecated:
  - `isLinkBiometricItemsToCurrentSet()` - use `PowerAuthBiometricConfiguration.isInvalidateBiometricFactorAfterChange()` instead.
  - `isConfirmBiometricAuthentication()` - use equal method in `PowerAuthBiometricConfiguration` instead.
  - `isAuthenticateOnBiometricKeySetup()` - use equal method in `PowerAuthBiometricConfiguration` instead.
  - `isFallbackToSharedBiometryKeyEnabled()` - use equal method in `PowerAuthBiometricConfiguration` instead.
  - `Builder.linkBiometricItemsToCurrentSet()` - use `PowerAuthBiometricConfiguration.Builder.invalidateBiometricFactorAfterChange(boolean)` instead.
  - `Builder.confirmBiometricAuthentication()` - use equal method in `PowerAuthBiometricConfiguration.Builder` instead.
  - `Builder.authenticateOnBiometricKeySetup()` - use equal method in `PowerAuthBiometricConfiguration.Builder` instead.
  - `Builder.enableFallbackToSharedBiometryKey()` - use equal method in `PowerAuthBiometricConfiguration.Builder` instead.

- The following classes and interfaces are now deprecated:
  - `IPersistActivationWithBiometricsListener` - use `IPersistActivationListener` instead.

- Due to removed support of recovery codes, the following classes and methods are no longer available:
  - Methods removed in `PowerAuthSDK`:
    - `createRecoveryActivation()`
    - `hasActivationRecoveryData()`
    - `getActivationRecoveryData()`
    - `confirmRecoveryCode()`
  - Methods removed in `PowerAuthActivation.Builder`:
    - all variants of `recoveryActivation()`
  - Methods removed in `ActivationCodeUtil`:
    - `parseFromRecoveryCode()`
    - `validateRecoveryCode()`
    - `validateRecoveryPuk()`
  - Other removed methods:
    - `CreateActivationResult.getRecoveryData()`
    - `ErrorResponseApiException.getCurrentRecoveryPukIndex()`
  - Removed classes and interfaces:
    - `IGetRecoveryDataListener`
    - `IConfirmRecoveryCodeListener`
    - `RecoveryData`

- The following functions now takes or returns `SecureData` instead of `byte[]`:
  - `PowerAuthSDK.persistActivationWithPassword()`
  - `PowerAuthSDK.addBiometryFactor()`
  - `PowerAuthSDK.setExternalEncryptionKey()`
  - `PowerAuthSDK.addExternalEncryptionKey()`
  - `PowerAuthConfiguration.getExternalEncryptionKey()`
  - `PowerAuthConfiguration.Builder.externalEncryptionKey()`
  - `PowerAuthAuthentication.getBiometryFactorRelatedKey()`
  - `PowerAuthAuthentication.getOverriddenPossessionKey()`
  - All static functions in `PowerAuthAuthentication` that takes custom possession or biometry key in parameter.
  - `IFetchEncryptionKeyListener.onFetchEncryptionKeySucceed()`
  - `CryptoUtils.ecdhComputeSharedSecret()`

- Removed all interfaces deprecated in release `1.9.x`

### Other changes

- TBA

## iOS & tvOS

Notable changes on iOS:

- Added the `PowerAuthCoreData` object to `PowerAuthCore` module to enhance in-memory management of sensitive data.

### API changes

- The following methods in `PowerAuthSDK` class are deprecated:
  - `unsafeChangePassword(from:to:)` - use asynchronous `changePassword(from:to:callback:)` as a replacement.
  - `persistActivation(with:)` - use asynchronous `persistActivation(with:callback:)` as a replacement.
  - `persistActivation(withPassword:)` - use asynchronous `persistActivation(withPassword:callback:)` as a replacement.
  - Constructor `PowerAuthSDK(configuration:keychainConfiguration:clientConfiguration:)` - use methods with `PowerAuthBiometricConfiguration` parameter instead.

- All static methods for accessing a various shared instances are now deprecated:
  - `PowerAuthSDK.initSharedInstance(...)` and `PowerAuthSDK.sharedInstance()` - To ensure better control and flexibility, manage the global instances within your application code.
  - `PowerAuthClientConfiguration.sharedInstance()` - use a class constructor with no parameters if you want to create the default configuration.
  - `PowerAuthKeychainConfiguration.sharedInstance()` - use a class constructor with no parameters if you want to create the default configuration.

- The following properties in `PowerAuthKeychainConfiguration` class are now deprecated:
  - `linkBiometricItemsToCurrentSet` - use new `PowerAuthBiometricConfiguration.invalidateBiometricFactorAfterChange` instead, with the same meaning.
  - `allowBiometricAuthenticationFallbackToDevicePasscode` - use new `PowerAuthBiometricConfiguration.allowFallbackToDevicePasscode` instead, with the same meaning.
  - `invalidateLocalAuthenticationContextAfterUse` - use new `PowerAuthBiometricConfiguration.invalidateLocalAuthenticationContextAfterUse` instead, with the same meaning.
  - Be aware that if you provide both, `PowerAuthBiometricConfiguration` and  `PowerAuthKeychainConfiguration` objects to initialize `PowerAuthSDK`, then the values from the biometric configuration takes precedence.

- Due to removed support of recovery codes, the following classes and methods are no longer available:
  - Methods removed in `PowerAuthSDK`:
    - `createActivation(withName:recoveryCode:recoveryPuk:extras:callback:)`
    - `hasActivationRecoveryData()`
    - `activationRecoveryData(authentication:callback:)`
    - `confirm(recoveryCode:, authentication:callback:)`
  - Methods removed in `PowerAuthActivationCodeUtil`:
    - `validateRecoveryCode()`
    - `validateRecoveryPuk()`
    - `parseFromRecoveryCode()`
  - Other changes:
    - removed class `PowerAuthActivationRecoveryData`
    - removed property `PowerAuthActivationResult.activationRecovery`
    - removed constructor `PowerAuthActivation(recoveryCode:recoveryPuk:name:)`

- The following functions or properties now takes or returns `PowerAuthCoreData` instead of `Data`:
  - `PowerAuthSDK.setExternalEncryptionKey()`
  - `PowerAuthSDK.addExternalEncryptionKey()`
  - `PowerAuthSDK.fetchEncryptionKey()`
  - `PowerAuthConfiguration.externalEncryptionKey`
  - All static functions in `PowerAuthAuthentication` that takes custom possession or biometry key in parameter.
  - `PowerAuthAuthentication.overridenPossessionKey` property is now `customPossessionKey`
  - `PowerAuthAuthentication.overridenBiometryKey` property is now `customBiometryKey`
  - `PowerAuthCoreCryptoUtils.ecdhComputeSharedSecret()`

- Removed all interfaces deprecated in release `1.9.x`

### Other changes

- TBA

## iOS & tvOS App Extensions

- The `PowerAuth2ForExtensions` library is now deprecated and no longer supported and maintained. You can use full feature PowerAuth mobile SDK as a replacement in your app extension.

## Known Bugs

The PowerAuth SDKs for watchOS, do not use time synchronized with the server for token-based authentication. To avoid any compatibility issues with the server, the authentication headers generated in your App Extension or on watchOS still use the older protocol version 3.1. This issue will be fixed in a future SDK update.

You can watch the following related issues:

- [wultra/powerauth-mobile-sdk#551](https://github.com/wultra/powerauth-mobile-sdk/issues/551)
- [wultra/powerauth-mobile-watch-sdk#7](https://github.com/wultra/powerauth-mobile-watch-sdk/issues/7)