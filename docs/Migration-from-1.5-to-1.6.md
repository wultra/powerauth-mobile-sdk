# Migration from 1.5.x to 1.6.x

PowerAuth Mobile SDK in version `1.6.0` is a maintenance release that brings multiple enhancements to both platforms:

- Android SDK now depends on Android Jetpack libraries instead of the deprecated support library. This is most important for biometric authentication. 
- iOS SDK is no longer in conflict with 3rd party OpenSSL libraries. Our implementation still depends on OpenSSL, but the dependency is now hidden in precompiled `PowerAuthCore` dynamic framework.
- iOS SDK has now unified class naming. So, no longer `PA2` vs `PowerAuth` class prefixes.  

### Compatibility with PowerAuth Server

- This release is fully compatible with PowerAuth Server version `0.24.x`, `1.0.x` and `1.1.x`.

## Android

### API changes

- PowerAuth mobile SDK now uses Jetpack libraries from `androidx` namespace as a replacement for old support library. If your application is still using the support library, then we highly recommend you to [migrate your code to AndroidX](https://developer.android.com/jetpack/androidx/migrate).
- PowerAuth mobile SDK now uses `androidx.biometry` for a biometric authentication, so you can upgrade this support library independently to PowerAuth mobile SDK. This is useful in case your users encounter a various device specific incompatibilities.
- All biometry-related API calls no longer accept `FragmentManager` as a parameter. You can now choose between variants with `Fragment` or `FragmentActivity` at input:
  - `PowerAuthSDK.commitActivation(Context, Fragment, String, String, String, ICommitActivationWithBiometryListener)`
  - `PowerAuthSDK.commitActivation(Context, FragmentActivity, String, String, String, ICommitActivationWithBiometryListener)`
  - `PowerAuthSDK.addBiometryFactor(Context, Fragment, String, String, String, IAddBiometryFactorListener)`
  - `PowerAuthSDK.addBiometryFactor(Context, FragmentActivity, String, String, String, IAddBiometryFactorListener)`
  - `PowerAuthSDK.authenticateUsingBiometry(Context, Fragment, String, String, IBiometricAuthenticationCallback)`
  - `PowerAuthSDK.authenticateUsingBiometry(Context, FragmentActivity, String, String, IBiometricAuthenticationCallback)`
  - All above methods must be called from UI thread, otherwise `IllegalStateException` is thrown.
- The `BiometricDialogResources` class containing resource IDs for the biometric authentication has been heavily reduced. Please review the actual usage of the resources carefuly.
  - The `BiometricDialogResources.Strings` section has been reduced. The old section constructor is now deprecated and you can review what strings are still in use.
  - The `BiometricDialogResources.Drawables` section has been reduced. The old section constructor is now deprecated and you can review what images are still in use. 
  - There's no longer `BiometricDialogResources.Colors` section. 
  - There's no longer `BiometricDialogResources.Layout` section.
- SDK no longer provide functions to detect root on device.
- All `PowerAuthErrorCodes.PA2ErrorCode*` constants are now deprecated. You can use a new constants with a standard naming for a replacement. For example `PA2ErrorCodeNetworkError` is now `NETWORK_ERROR`.
- The following classes and interfaces are now deprecated:
  - `PA2System` class is now `PowerAuthSystem`
  - `PA2Log` class is now `PowerAuthLog`
  - `PA2ClientValidationStrategy` interface is now `HttpClientValidationStrategy`
  - `PA2ClientSslNoValidationStrategy` class is now `HttpClientSslNoValidationStrategy`
  - `Otp` class is now `ActivationCode` available in package `io.getlime.security.powerauth.core`
  - `OtpUtil` class is now `ActivationCodeUtil` available in package `io.getlime.security.powerauth.core`

### Other changes

- If your application is using an asymmetric cipher protecting the biometric key (e.g. `PowerAuthKeychainConfiguration.isAuthenticateOnBiometricKeySetup` is `false`), then the methods configuring new biometric key may take a longer time calculating the key-pair on the background thread. The PowerAuth mobile SDK doesn't display any biometric authentication dialog in this case, so your application's UI should display some activity indicator. The following methods are affected by this change:
  - `PowerAuthSDK.commitActivation(Context, Fragment | FragmentActivity, String, String, String, ICommitActivationWithBiometryListener)`
  - `PowerAuthSDK.addBiometryFactor(Context, Fragment | FragmentActivity, String, String, String, IAddBiometryFactorListener)`

- `PowerAuthSDK.createActivation(...)` methods now reprots a slightly different error codes when invalid activation or recovery code is provided. If your application properly validate input data with using `ActivationCodeUtil`, then this change should not affect your code.

## iOS & tvOS

The main change in this SDK version is that SDK is now composed from two dynamic frameworks:

- `PowerAuthCore` - module contains low level implementation and has embedded OpenSSL.
- `PowerAuth2` - module contains all high level SDK source codes and depends on `PowerAuthCore`

<!-- begin box warning -->
Version 1.6.6 increased minimum required iOS & tvOS deployment target to 11.0. See [Xcode14 support](#xcode14-support).
<!-- end -->

### API changes

- All public objects, protocols, enums, constants and functions now have `PowerAuth` prefix. All previously declared `PA2*` interfaces are now declared as deprecated. 
  - For example, `PA2ActivationStatus` is now deprecated and you should use `PowerAuthActivationStatus` instead. The similar rename can be applied for all deprecated interfaces.
  - This change normally works well for swift enumerations, because enumeration values are mangled to a short names, like `.removed`. For ObjC projects, it's recommended to use project-wide find'n'replace. For example, for `PA2ActivationState_` you can replace all occurrences to `PowerAuthActivationState_`.
  - You may encounter a several compilation errors at the beginning. If so, then it's recommended to fix the deprecation warnings first, because that may also solve that compilation errors.  
- ECIES routines are now provided by new `PowerAuthCore` module, so in case your application depends on our E2E encryption scheme, then you have add `import PowerAuthCore` first and then fix the deprecated warnings.
- SDK no longer provide functions to detect jailbreak on device.
- `PowerAuthActivation` object constructor now throws an error in Swift. If you don't care about the error, then use `try?` statement to achieve previous constructor behavior.

List of renamed interfaces:

- Configuration
  - `PA2ClientConfiguration` is now `PowerAuthClientConfiguration`
  - `PA2KeychainConfiguration` is now `PowerAuthKeychainConfiguration`
- Activation
  - `PA2ActivationState` enum is now `PowerAuthActivationState`.
  - `PA2ActivationStatus` is now `PowerAuthActivationStatus`
  - `PA2ActivationResult` is now `PowerAuthActivationResult`
  - `PA2ActivationRecoveryData` is now `PowerAuthActivationRecoveryData`
  - `PA2Otp` is now `PowerAuthActivationCode`
  - `PA2OtpUtil` is now `PowerAuthActivationCodeUtil`
- Signatures
  - `PA2AuthorizationHttpHeader` is now `PowerAuthAuthorizationHttpHeader`
- Error handling
  - `PA2ErrorDomain` constant is now `PowerAuthErrorDomain` (our `NSError` domain)
  - `PA2ErrorCode*` constants are now replaced by `PowerAuthErrorCode` enum.
    - You can use `NSError.powerAuthErrorCode` to acquire a fully typed error code from `NSError` object.
  - `PA2ErrorInfoKey_AdditionalInfo` constant is now `PowerAuthErrorInfoKey_AdditionalInfo` (key to `NSError.userInfo` dictionary)
  - `PA2ErrorInfoKey_ResponseData` constant is now `PowerAuthErrorInfoKey_ResponseData` (key to `NSError.userInfo` dictionary)
  - `PA2Error` is now `PowerAuthRestApiError` (REST API object received in case of error)
  - `PA2ErrorResponse` is now `PowerAuthRestApiErrorResponse` (REST API response object, containing full information about failure)
  - `PA2RestResponseStatus` enum is now `PowerAuthRestApiResponseStatus` (enum contains `OK` or `ERROR` constants)
- Networking
  - `PA2HttpRequestInterceptor` protocol is now `PowerAuthHttpRequestInterceptor`
  - `PA2CustomHeaderRequestInterceptor` is now `PowerAuthCustomHeaderRequestInterceptor`
  - `PA2BasicHttpAuthenticationRequestInterceptor` is now `PowerAuthBasicHttpAuthenticationRequestInterceptor`
  - `PA2ClientSslValidationStrategy` protocol is now `PowerAuthClientSslValidationStrategy`
  - `PA2ClientSslNoValidationStrategy` is now `PowerAuthClientSslNoValidationStrategy`
- Keychain
  - `PA2Keychain` is now `PowerAuthKeychain`
  - `PA2KeychainItemAccess` enum is now `PowerAuthKeychainItemAccess`
  - `PA2BiometricAuthenticationInfo` structure is now `PowerAuthBiometricAuthenticationInfo`
  - `PA2BiometricAuthenticationStatus` enum is now `PowerAuthBiometricAuthenticationStatus`
  - `PA2BiometricAuthenticationType` enum is now `PowerAuthBiometricAuthenticationType`
  - `PA2KeychainStoreItemResult` enum is now `PowerAuthKeychainStoreItemResult`
  - `PA2Keychain_Initialized` constant is now `PowerAuthKeychain_Initialized`
  - `PA2Keychain_Status` constant is now `PowerAuthKeychain_Status`		
  - `PA2Keychain_Possession` constant is now `PowerAuthKeychain_Possession`	
  - `PA2Keychain_Biometry` constant is now `PowerAuthKeychain_Biometry`		
  - `PA2Keychain_TokenStore` constant is now `PowerAuthKeychain_TokenStore`	
  - `PA2KeychainKey_Possession` constant is now `PowerAuthKeychainKey_Possession`
- Other interfaces
  - `PA2WCSessionManager` is now `PowerAuthWCSessionManager`
  - `PA2OperationTask` protocol is now `PowerAuthOperationTask`
  - `PA2System` is now `PowerAuthSystem`
  - `PA2LogSetEnabled()` function is now `PowerAuthLogSetEnabled()`
  - `PA2LogIsEnabled()` function is now `PowerAuthLogIsEnabled()`
  - `PA2LogSetVerbose()` function is now `PowerAuthLogSetVerbose()`
  - `PA2LogIsVerbose()` function is now `PowerAuthLogIsVerbose()`
- Interfaces moved to `PowerAuthCore` module
  - `PA2Password` is now `PowerAuthCorePassword`
  - `PA2MutablePassword` is now `PowerAuthCoreMutablePassword`
  - `PA2ECIESEncryptor` is now `PowerAuthCoreEciesEncryptor`
  - `PA2ECIESCryptogram` is now `PowerAuthCoreEciesCryptogram`
  - `PA2ECIESMetaData` is now `PowerAuthCoreEciesMetaData`
  - `PA2ECIESEncryptorScope` enum is now `PowerAuthCoreEciesEncryptorScope`
  - `PA2CryptoUtils` is now `PowerAuthCoreCryptoUtils`
  - `PA2ECPublicKey` is now `PowerAuthCoreECPublicKey`
    
### Other changes

- `PowerAuthErrorCodes` contains new `.invalidActivationCode` constant, reported in case that invalid activation or recovery code is provided to `PowerAuthSDK.createActivation(...)` method. If your application properly validate input data with using `PowerAuthActivationCodeUtil`, then this change should not affect your code.


## iOS & tvOS App Extensions

The `PowerAuth2ForExtensions` is now distributed as a dynamic module, instead of static framework.

<!-- begin box warning -->
Version 1.6.6 increased minimum required iOS & tvOS deployment target to 11.0. See [Xcode14 support](#xcode14-support).
<!-- end -->

### API changes

- All public objects, protocols, enums, constants and functions now have `PowerAuth` prefix. All previously declared `PA2*` interfaces are now declared as deprecated.

List of renamed interfaces:

- `PA2ExtensionLibrary` is now `PowerAuthSystem`
- `PA2ErrorDomain` constant is now `PowerAuthErrorDomain` (our `NSError` domain)
- `PA2ErrorCode*` constants are now replaced by `PowerAuthErrorCode` enum.
  - You can use `NSError.powerAuthErrorCode` to acquire a fully typed error code from `NSError` object.
- `PA2ErrorInfoKey_AdditionalInfo` constant is now `PowerAuthErrorInfoKey_AdditionalInfo` (key to `NSError.userInfo` dictionary)
- `PA2ErrorInfoKey_ResponseData` constant is now `PowerAuthErrorInfoKey_ResponseData` (key to `NSError.userInfo` dictionary)
- `PA2KeychainConfiguration` is now `PowerAuthKeychainConfiguration`
- `PA2Keychain` is now `PowerAuthKeychain` (see iOS migration note for the rest of changes in keychain-related interfaces)
- `PA2LogSetEnabled()` function is now `PowerAuthLogSetEnabled()`
- `PA2LogIsEnabled()` function is now `PowerAuthLogIsEnabled()`
- `PA2LogSetVerbose()` function is now `PowerAuthLogSetVerbose()`
- `PA2LogIsVerbose()` function is now `PowerAuthLogIsVerbose()`

## watchOS

<!-- begin box warning -->
Version 1.6.6 increased minimum required watchOS deployment target to 4.0. See [Xcode14 support](#xcode14-support).
<!-- end -->

The `PowerAuth2ForWatch` is now distributed as a dynamic module, instead of static framework.

### API changes

- All public objects, protocols, enums, constants and functions now have `PowerAuth` prefix. All previously declared `PA2*` interfaces are now declared as deprecated.

List of renamed interfaces:

- `PA2ExtensionLibrary` is now `PowerAuthSystem`
- `PA2WCSessionManager` is now `PowerAuthWCSessionManager`
- `PA2ErrorDomain` constant is now `PowerAuthErrorDomain` (our `NSError` domain)
- `PA2ErrorCode*` constants are now replaced by `PowerAuthErrorCode` enum.
  - You can use `NSError.powerAuthErrorCode` to acquire a fully typed error code from `NSError` object.
- `PA2ErrorInfoKey_AdditionalInfo` constant is now `PowerAuthErrorInfoKey_AdditionalInfo` (key to `NSError.userInfo` dictionary)
- `PA2ErrorInfoKey_ResponseData` constant is now `PowerAuthErrorInfoKey_ResponseData` (key to `NSError.userInfo` dictionary)
- `PA2KeychainConfiguration` is now `PowerAuthKeychainConfiguration`
- `PA2Keychain` is now `PowerAuthKeychain` (see iOS migration note for the rest of changes in keychain-related interfaces)
- `PA2LogSetEnabled()` function is now `PowerAuthLogSetEnabled()`
- `PA2LogIsEnabled()` function is now `PowerAuthLogIsEnabled()`
- `PA2LogSetVerbose()` function is now `PowerAuthLogSetVerbose()`
- `PA2LogIsVerbose()` function is now `PowerAuthLogIsVerbose()`


## Changes in 1.6.6+

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

If you use cocoapds for PowerAuth mobile SDK integration, then please let us know and we'll prepare a special release branch for you.