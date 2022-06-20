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

- Method `PowerAuthSDK.removeActivationLocal(Context, boolean)` has no longer the context parameter optional, so the Context has to be always provided.

- Property `PowerAuthAuthentication.overridenPossessionKey` is now `overriddenPossessionKey` (fixed typo in property name.)

### Other changes

- `BiometricAuthentication.isBiometricAuthenticationAvailable()` now better reflect the biometric authentication availability. The function is now internally implemented as `BiometricAuthentication.canAuthenticate() == BiometricStatus.OK`.

- If you try to request for the same access token but with a different set of factors in `PowerAuthAuthentication`, then the request will fail with `WRONG_PARAMETER` error code.

- PowerAuth mobile SDK is now using custom "User-Agent" for all HTTP requests initiated from the library.
  - You can see how's user agent string constructed by calling `PowerAuthSystem.getDefaultUserAgent(context)`.
  - To set the previous networking behavior, you can set `""` (empty string) to userAgent property of PowerAuthClientConfiguration:
    ```java
    final PowerAuthClientConfiguration clientConfiguration = new PowerAuthClientConfiguration.Builder()
                    .userAgent("")
                    .build();
    ``` 

## iOS & tvOS

- TBA

### API changes

- `PowerAuthSDK.lastFetchedCustomObject` property is now deprecated. The custom object dictionary is now a part of `PowerAuthActivationStatus` object.
- `PowerAuthSDK.fetchActivationStatus` has now a different callback function, with no custom object dictionary in the callback parameter.
  - The original function is marked as deprecated, so if you're not interested in the custom object, then simply remove that parameter from the callback. The Swift compiler should re-map the call to a proper Objective-C message from SDK. If you're using Objective-C, then use `getActivationStatusWithCallback` message as a replacement.
- `PowerAuthSDK` no longer provide `session` property. If you still need access to low-level `PowerAuthCoreSession`, then use `sessionProvider` as a replacement. The property contains object implementing new `PowerAuthCoreSessionProvider` protocol.
- `PowerAuthCoreSession.prepareKeyValueDictionaryForDataSigning()` is now static method.
- `PowerAuthCoreSession.generateActivationStatusChallenge()` is now static method.
- All asynchronous methods in `PowerAuthKeychain` are now deprecated. You should use synchronous methods as a replacement.
- All methods with biometry prompt in `PowerAuthKeychain` are now deprecated. You can use new methods with `PowerAuthKeychainAuthentication` as a replacement.
- All asynchronous methods from `PowerAuthTokenStore` protocol now returns objects conforming to `PowerAuthOperationTask` and therefore the returned operation can be canceled directly.
- `PowerAuthTokenStore.cancelTask()` is now deprecated. You can cancel the returned asynchronous operation directly.
    
### Other changes

- If you try to request for the same access token but with a different set of factors in `PowerAuthAuthentication`, then the request will fail with `wrongParameter` error code.

- PowerAuth mobile SDK is now using custom "User-Agent" for all HTTP requests initiated from the library.
  - You can see how's user agent string constructed by reading a new `userAgent` property of `PowerAuthClientConfiguration` object.
  - To set the previous networking behavior, you can set `nil` 

## iOS & tvOS App Extensions

- TBA

### API changes

- All asynchronous methods in `PowerAuthKeychain` are now deprecated. You should use synchronous methods as a replacement.
- All methods with biometry prompt in `PowerAuthKeychain` are now deprecated. You can use new methods with `PowerAuthKeychainAuthentication` as a replacement.
- `PowerAuthTokenStore.removeLocalToken()` and `PowerAuthTokenStore.removeAllLocalTokens|()` functions are now disabled for app extensions. You have to manage tokens from the main application now.

## watchOS

- TBA

### API changes

- All asynchronous methods in `PowerAuthKeychain` are now deprecated. You should use synchronous methods as a replacement.
- All methods with biometry prompt in `PowerAuthKeychain` are now deprecated. You can use new methods with `PowerAuthKeychainAuthentication` as a replacement.
- `PowerAuthWatchSDK.activationId` property is now deprecated. Please use `activationIdentifier` as a replacement.
- All asynchronous methods from `PowerAuthTokenStore` protocol now returns objects conforming to `PowerAuthOperationTask` and therefore the returned operation can be canceled directly.
- `PowerAuthTokenStore.cancelTask()` is now deprecated. You can cancel the returned asynchronous operation directly.
