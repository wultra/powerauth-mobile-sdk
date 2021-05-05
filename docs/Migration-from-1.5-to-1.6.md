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
  - All above methods must be called from UI thread, otherwise `IllegalStateException` is thrown.
- The `BiometricDialogResources` class containing resource IDs for the biometric authentication has been heavily reduced. Please review the actual usage of the resources carefuly.
  - The `BiometricDialogResources.Strings` section has been reduced. The old section constructor is now deprecated and you can review what strings are still in use.
  - The `BiometricDialogResources.Drawables` section has been reduced. The old section constructor is now deprecated and you can review what images are still in use. 
  - There's no longer `BiometricDialogResources.Colors` section. 
  - There's no longer `BiometricDialogResources.Layout` section.
- SDK no longer provide functions to detect root on device. 

## iOS

The main change in this SDK version is that SDK is now composed from two dynamic frameworks:

- `PowerAuthCore` - module contains low level implementation and has embedded OpenSSL.
- `PowerAuth2` - module contains all high level SDK source codes and depends on `PowerAuthCore`



### API changes

- All public objects, protocols, enums, constants and functions now have `PowerAuth` prefix. All previously declared `PA2*` interfaces are now declared as deprecated. 
  - For example, `PA2ActivationStatus` is now deprecated and you should use `PowerAuthActivationStatus` instead. The similar rename can be applied for all deprecated interfaces.
  - This change normally works well for swift enumerations, because enumeration values are mangled to a short names, like `.removed`. For ObjC projects, it's recommended to use project-wide find'n'replace. For example, for `PA2ActivationState_` you can replace all occurrences to `PowerAuthActivationState_`.
  - You may encounter a several compilation errors at the beginning. If so, then it's recommended to fix the deprecation warnings first, because that may also solve that compilation errors.  
- ECIES routines are now provided by new `PowerAuthCore` module, so in case your application depends on our E2E encryption scheme, then you have add `import PowerAuthCore` first and then fix the deprecated warnings.
- SDK no longer provide functions to detect jailbreak on device.

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
    
## iOS App Extensions

The `PowerAuth2ForExtensions` is now distributed as a dynamic module, instead of static framework.

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