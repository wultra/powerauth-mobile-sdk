# Migration from 1.6.x to 1.7.x

PowerAuth Mobile SDK in version `1.7.0` is a maintenance release that brings multiple enhancements to both platforms:

- iOS SDK introduces a new feature that allows you to share activation across multiple apps from the same vendor.
- Added missing nullability annotations to Android SDK.
- Both platforms have improved PowerAuth Token internal implementations. For example, your networking code can ask for the named token simultaneously without worrying that multiple tokens are created on the server.
- Improved usage of `PowerAuthAuthentication` object on both platforms.

### Compatibility with PowerAuth Server

- This release is fully compatible with PowerAuth Server version `0.24.x` up to `1.3.x`.

## Android

### API changes

- All mutable properties in `PowerAuthAuthentication` are now deprecated, including `PowerAuthAuthentication()` (constructor with no parameters). You can use the following static methods as a replacement:
  - `PowerAuthAuthentication.possession()` - create authentication object for signing with possession factor only.
  - `PowerAuthAuthentication.possessionWithPassword()` - create authentication object for signing with possession and knowledge factors.
  - `PowerAuthAuthentication.possessionWithBiometry()` - create authentication object for signing with possession and biometry factors.
  - `PowerAuthAuthentication.commitWithPassword()` - create authentication object for activation commit purpose.
  - `PowerAuthAuthentication.commitWithPasswordAndBiometry()` - create authentication object for activation commit purpose.
  - `getPassword()` (e.g. `password` in Kotlin) is a new replacement for getting value of deprecated `usePassword`. The function returns `Password` object since SDK version 1.7.2.
  
  If you see no deprecation warnings in your application code, then please add the following lines into your `build.gradle` file:
  ```gradle
  compileKotlin {
      kotlinOptions {
          suppressWarnings false
      }
  }
  ```

- Added `@NonNull` annotations to all public "listener" interfaces:
  - `IActivationRemoveListener`
  - `IActivationStatusListener`
  - `IChangePasswordListener`
  - `IDataSignatureListener`
  - `IFetchEncryptionKeyListener`
  - `IValidatePasswordListener`
  
  This change may lead to a several errors if application is written in Kotlin. This is due to fact that Kotlin will not be able to override original methods because nullable type is different than non-null. To fix this, simply remove `?` from the conflicting type, for example, if method is `onPasswordValidationFailed(t: Throwable?)`, then simply change `Throwable?` to `Throwable`.
  
- Interface `IFetchKeysStrategy` is now deprecated and will be removed in the next major SDK release.
  - There's `IPossessionFactorEncryptionKeyProvider` that SDK is using internally as a replacement. If your application depends on `IFetchKeysStrategy`, then please contact us to find a proper solution for you.

- Method `PowerAuthSDK.removeActivationLocal(Context, boolean)` has no longer the context parameter optional, so the Context has to be always provided.

- Property `PowerAuthAuthentication.overridenPossessionKey` is now `overriddenPossessionKey` (fixed typo in property name.)

### Other changes

- Be aware that PowerAuthSDK now validates the purpose of `PowerAuthAuthentication` object. For example, if authentication object is created for activation commit and then is used for the signature calculation, then the warning is reported to the debug console. The future SDK versions will report an error in this situation. 

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

- `IOException` is no longer reported from SDK's internal networking. Now all such exceptions are wrapped into `PowerAuthErrorException` with `NETWORK_ERROR` code set.

- Please read also [Changes introduced in 1.7.2](#changes-in-172) version.

## iOS & tvOS

<!-- begin box warning -->
Version 1.7.3 increased minimum required iOS & tvOS deployment target to 11.0.
<!-- end -->

### API changes

- All mutable properties in `PowerAuthAuthentication` are now deprecated, including `PowerAuthAuthentication()` (constructor with no parameters). You can use the following static methods as a replacement:
  - `PowerAuthAuthentication.possession()` - create authentication object for signing with possession factor only.
  - `PowerAuthAuthentication.possessionWithPassword(password:)` - create authentication object for signing with possession and knowledge factors.
  - `PowerAuthAuthentication.possessionWithBiometry()` - create authentication object for signing with possession and biometry factors.
  - `PowerAuthAuthentication.possessionWithBiometry(prompt:)` - create authentication object for signing with possession and biometry factors, with dialog prompt.
  - `PowerAuthAuthentication.commitWithPassword(password:)` - create authentication object for activation commit purpose.
  - `PowerAuthAuthentication.commitWithPasswordAndBiometry(password:)` - create authentication object for activation commit purpose.

- Following methods in `PowerAuthAuthentication` are now deprecated:
  - `PowerAuthAuthentication.possession(withPassword:)` is now replaced with `.possessionWithPassword(password:)`
  - `PowerAuthAuthentication.possessionWithBiometry(withPrompt:)` is is now replaced with `.possessionWithBiometry(prompt:)`

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

- Be aware that PowerAuthSDK now validates the purpose of `PowerAuthAuthentication` object. For example, if authentication object is created for activation commit and then is used for the signature calculation, then the warning is reported to the debug console. The future SDK versions will report an error in this situation.  

- If you try to request for the same access token but with a different set of factors in `PowerAuthAuthentication`, then the request will fail with `wrongParameter` error code.

- PowerAuth mobile SDK is now using custom "User-Agent" for all HTTP requests initiated from the library.
  - You can see how's user agent string constructed by reading a new `userAgent` property of `PowerAuthClientConfiguration` object.
  - To set the previous networking behavior, you can set `nil`
  
- Please read also [Changes introduced in 1.7.2](#changes-in-172) version.

## iOS & tvOS App Extensions

### API changes

- All asynchronous methods in `PowerAuthKeychain` are now deprecated. You should use synchronous methods as a replacement.
- `PowerAuthTokenStore.removeLocalToken()` and `PowerAuthTokenStore.removeAllLocalTokens|()` functions are now disabled for app extensions. You have to manage tokens from the main application now.

## watchOS

<!-- begin box warning -->
Version 1.7.3 increased minimum required watchOS deployment target to 4.0.
<!-- end -->

### API changes

- All asynchronous methods in `PowerAuthKeychain` are now deprecated. You should use synchronous methods as a replacement.
- `PowerAuthWatchSDK.activationId` property is now deprecated. Please use `activationIdentifier` as a replacement.
- All asynchronous methods from `PowerAuthTokenStore` protocol now returns objects conforming to `PowerAuthOperationTask` and therefore the returned operation can be canceled directly.
- `PowerAuthTokenStore.cancelTask()` is now deprecated. You can cancel the returned asynchronous operation directly.


## Changes in 1.7.2+

### Android

The following interfaces are marked as deprecated since 1.7.2 version:

- `PowerAuthSDK.validatePasswordCorrect()` function is now deprecated. You can use `validatePassword()` function as a replacement.

- Direct access to `PowerAuthAuthentication.usePassword` property is no longer possible. Application written in Kotlin will report warning, due to mapping to new, but already deprecated `setUsePassword()` or `getUsePassword()` functions. To test whether knowledge factor is set in authentication object, use `getPassword()` function. The function was introduced in version 1.7.0, but it's returned value is now `Password` object, instead of `String`.

### iOS & tvOS

- Changed value returned from `PowerAuthCorePassword.validatePasswordComplexity()` function, including the prototype of the validation block. 

The following interfaces are marked as deprecated since 1.7.2 version:

- `PowerAuthSDK.validatePasswordCorrect(_, callback:)` is deprecated, use `validatePassword(password:, callback:)` as a replacement.

- `PowerAuthSDK.addBiometryFactor(_, callback)` is deprecated, use `addBiometryFactor(password:, callback:)` as a replacement.

- Using `PowerAuthAuthentication.usePassword` property is now deprecated. To test whether authentication has the knowledge factor set, use `password` property, which contains nullable `PowerAuthCorePassword` object.


## Changes in 1.7.3+

### Xcode14 support

Due to changes in Xcode 14, bitcode is no longer supported and we had to increase minimum supported OS to the following versions:

- iOS 11.0
- tvOS 11.0
- watchOS 4.0

If you still have to compile our SDK for older operating systems, then you need to build the library manually with Xcode older than 14.0. For example:

1. Clone repository
   ```bash
   git clone --recursive https://github.com/wultra/powerauth-mobile-sdk.git
   cd powerauth-mobile-sdk
   git submodule update
   ```
1. Make sure that xcodebuild is older than 14.0:
   ```bash
   % xcodebuild -version
   Xcode 13.2.1
   Build version 13C100
   ```
1. Build library with legacy architectures and bitcode:
   ```bash
   ./scripts/ios-build-sdk.sh buildCore buildSdk --legacy-archs --use-bitcode --out-dir ./Build
   ```
   Similar command is available for app extensions and watchos:
   ```bash
   ./scripts/ios-build-extensions.sh extensions watchos --legacy-archs --use-bitcode --out-dir ./Build
   ```

If you use cocoapds for PowerAuth SDK integration, then you can apply the following additional steps:

1. Fork `wultra/powerauth-mobile-sdk` repository 
1. Change `PowerAuth2.podspec` and `PowerAuthCore.podspec` in your fork:
   - Update iOS & tvOS `deployment_target` to `9.0`
   - In `PowerAuthCore.podspec`, alter `prepare_command` by adding `--legacy-archs` or `--use-bitcode` switch
1. In your application, alter dependency on `PowerAuth2` (you need to add additional dependency on `PowerAuthCore`, otherwise pod tool will use our official build):
   - `pod 'PowerAuth2', :git => 'https://github.com/{your-fork}.git', :branch => 'develop', :submodules => true`
   - `pod 'PowerAuthCore', :git => 'https://github.com/{your-fork}.git', :branch => 'develop', :submodules => true`
