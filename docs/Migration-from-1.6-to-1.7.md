# Migration from 1.6.x to 1.7.x

PowerAuth Mobile SDK in version `1.7.0` is a maintenance release that brings multiple enhancements to both platforms:

- TBA  

### Compatibility with PowerAuth Server

- This release is fully compatible with PowerAuth Server version `0.24.x`, `1.0.x` and `1.1.x`.

## Android

### API changes

- Added `@NonNull` annotations to all public "listener" interfaces. This change may produce several warnings in application's code. The following interfaces are affected:
  - `IActivationRemoveListener`
  - `IActivationStatusListener`
  - `IChangePasswordListener`
  - `IDataSignatureListener`
  - `IFetchEncryptionKeyListener`
  - `IValidatePasswordListener`
  
- Interface `IFetchKeysStrategy` is now deprecated and will be removed in the next major SDK release.
  - There's `IPossessionFactorEncryptionKeyProvider` that SDK is using internally as a replacement. If your application depends on `IFetchKeysStrategy`, then please contact us to find a proper solution for you.

### Other changes

- `BiometricAuthentication.isBiometricAuthenticationAvailable()` now better reflect the biometric authentication availability. The function is now internally implemented as `BiometricAuthentication.canAuthenticate() == BiometricStatus.OK`.

## iOS & tvOS

- TBA

### API changes

- `PowerAuthSDK` no longer provide `session` property. If you still need access to low-level `PowerAuthCoreSession`, then use `sessionProvider` as a replacement. The property contains object implementing new `PowerAuthCoreSessionProvider` protocol.
- `PowerAuthCoreSession.prepareKeyValueDictionaryForDataSigning()` is now static method.
- `PowerAuthCoreSession.generateActivationStatusChallenge()` is now static method.
- All asynchronous methods in `PowerAuthKeychain` are now deprecated. You should use synchronous methods as a replacement.
- All methods with biometry prompt in `PowerAuthKeychain` are now deprecated. You can use new methods with `PowerAuthKeychainAuthentication` as a replacement.
    
### Other changes

- TBA

## iOS & tvOS App Extensions

- TBA

### API changes

- All asynchronous methods in `PowerAuthKeychain` are now deprecated. You should use synchronous methods as a replacement.
- All methods with biometry prompt in `PowerAuthKeychain` are now deprecated. You can use new methods with `PowerAuthKeychainAuthentication` as a replacement.

## watchOS

- TBA

### API changes

- All asynchronous methods in `PowerAuthKeychain` are now deprecated. You should use synchronous methods as a replacement.
- All methods with biometry prompt in `PowerAuthKeychain` are now deprecated. You can use new methods with `PowerAuthKeychainAuthentication` as a replacement.