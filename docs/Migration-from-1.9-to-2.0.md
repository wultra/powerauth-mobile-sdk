# Migration from 1.9.x to 2.0.x

PowerAuth Mobile SDK in version `2.0.0` provides the following improvements:

- PowerAuth protocol version 4.0 introduces major cryptographic upgrades to strengthen long-term security and add post-quantum protection. Signature and key agreement mechanisms now use larger elliptic curves (P-384) and optionally operate in hybrid mode with quantum-resistant ML-DSA and ML-KEM algorithms. The end-to-end encryption scheme transitions from ECIES with AES-128/CBC and HMAC-SHA-256 to an AEAD design using AES-256/CTR with KMAC-256, providing stronger integrity and confidentiality guarantees. Overall, version 4.0 modernizes the protocol to align with emerging cryptographic standards and resist future quantum attacks.
- Existing activations can be upgraded to the new PowerAuth protocol version 4.0 using the authenticated protocol upgrade procedure.
- You can select a level of security that suits your business needs. See the `PowerAuthConfiguration` documentation for more details.
- PowerAuth Mobile SDK can optionally operate in a mode fully compatible with legacy PowerAuth protocol version 3.3.
- A new `PowerAuthBiometricConfiguration` class simplifies biometric configuration of the `PowerAuthSDK` class.
- A new `PowerAuthSecureVaultKey` class provides better flexibility for Secure Vault operations.
- PowerAuth Mobile SDK now ensures sensitive keys are not retained in memory.
- Activation using a recovery code is no longer supported.
- External encryption key feature is discontinued and will be removed in the next SDK release.

### Compatibility with PowerAuth Server

- This release is fully compatible with PowerAuth Server version `2.0.0` and later.
- If you configure `PowerAuthSDK` to operate with the legacy PowerAuth protocol 3.3, it requires PowerAuth Server version `1.9.0` or later.

## Android

Notable changes on Android:

- New `PowerAuthBiometricPrompt` class simplifies biometric key setup and authentication.
- Added the `SecureData` class to `io.getlime.security.powerauth.core` package to enhance in-memory management of sensitive data.

### API changes

- The following methods or properties are now deprecated or changed:
  - `PowerAuthSDK` class:
    - `changePasswordUnsafe()` - use asynchronous `changePassword()` as a replacement.
    - `persistActivationWithAuthentication()` - use asynchronous variant with `IPersistActivationListener` as a callback parameter.
    - `persistActivationWithPassword()` - use asynchronous variant with `IPersistActivationListener` as a callback parameter.
    - `persistActivation(..., IPersistActivationWithBiometricsListener)` - use asynchronous method with `IPersistActivationListener` as a callback parameter.
    - All variants of `addBiometryFactor()` with "title" and "description" parameters are now replaced with variant using `PowerAuthBiometricPrompt`.
    - `removeBiometryFactor()` - use asynchronous variant with `IRemoveBiometryFactorListener` as a callback parameter.
    - `authenticateUsingBiometrics()` - with "title" and "description" parameters, use variant with `PowerAuthBiometricPrompt` parameter instead.
    - `requestGetSignatureWithAuthentication()` - use `authenticationHeaderForRequestWithParams()` method instead which throws an exception in case of failure.
    - `requestSignatureWithAuthentication()` - use `authenticationHeaderForRequestWithBody()` method instead which throws an exception in case of failure.
    - `offlineSignatureWithAuthentication()` - use asynchronous `offlineAuthenticationCode()` method instead.
    - `signDataWithDevicePrivateKey()` - use `calculateDigitalSignature()` method where you can specify the key used for signing.
    - `signJwtWithDevicePrivateKey()` - use `calculateJwsSignature()` method where you can specify the key used for signing.
    - `verifyServerSignedData()` - use `verifyDigitalSignature()` method where you can specify the key used for verification.
    - `createSignedCSR()` - use `createCertificateSigningRequest()` method where you can specify the key to use for CSR creation.
    - `fetchEncryptionKey()` - method is effective only if PowerAuthSDK is running at protocol 3.3 and will be removed once we drop support for this legacy protocol. Meanwhile you can migrate to the new `fetchSecureVaultKey()` method providing a better flexibility for secure vault operations.
    - `saveSerializedState()` - method is now private
    - `restoreState()` - method is now private
    - `getSession()` - access to a low-level session object is no longer available. Let us know if you have a problem with this.

  - `PowerAuthConfiguration` class:
    - `getOfflineSignatureComponentLength()` - use `getOfflineAuthenticationCodeComponentLength()` instead.
    - `isAutomaticProtocolUpgradeDisabled()` - always returns `false`.

  - `PowerAuthConfiguration.Builder` class:
    - `offlineSignatureComponentLength()` - use `offlineAuthenticationCodeComponentLength()` instead.
    - `disableAutomaticProtocolUpgrade()` - has no effect.
    - `build()` - method now throws `PowerAuthErrorException` if wrong configuration is provided.

  - `IPersistActivationListener` callback interface:
    - `onPersistActivationFailed()` method now receives `Throwable` instead of `PowerAuthErrorException`. You can also expect `FailedApiException` and similar exceptions if communication with the server failed.
  
  - `IDataSignatureListener` callback interface is deprecated, use API method that takes `IDigitalSignatureListener` listener at input.

  - `IJwtSignatureListener` callback interface is deprecated, use API method that takes `IJwsSignatureListener` listener at input.

  - `IGenerateTokenHeaderListener` callback interface:
    - `onGenerateTokenHeaderSucceeded()` method now receives `PowerAuthHttpHeader` object.

  - `ICreateCSRListener` callback interface is deprecated and replaced by `ICreateCertificateSigningRequestListener`. Be aware that the new interface takes `Throwable` instead of `PowerAuthErrorException` in case of failure. You can expect `FailedApiException` and similar exceptions if communication with the server failed.

  - `PowerAuthKeychainConfiguration` class:
    - `isLinkBiometricItemsToCurrentSet()` - use `PowerAuthBiometricConfiguration.isInvalidateBiometricFactorAfterChange()` instead.
    - `isConfirmBiometricAuthentication()` - use equal method in `PowerAuthBiometricConfiguration` instead.
    - `isAuthenticateOnBiometricKeySetup()` - use equal method in `PowerAuthBiometricConfiguration` instead.
    - `isFallbackToSharedBiometryKeyEnabled()` - use equal method in `PowerAuthBiometricConfiguration` instead.
    - `Builder.linkBiometricItemsToCurrentSet()` - use `PowerAuthBiometricConfiguration.Builder.invalidateBiometricFactorAfterChange(boolean)` instead.
    - `Builder.confirmBiometricAuthentication()` - use equal method in `PowerAuthBiometricConfiguration.Builder` instead.
    - `Builder.authenticateOnBiometricKeySetup()` - use equal method in `PowerAuthBiometricConfiguration.Builder` instead.
    - `Builder.enableFallbackToSharedBiometryKey()` - use equal method in `PowerAuthBiometricConfiguration.Builder` instead.

  - `PowerAuthToken` class:
    - `generateHeader()` - use `generateTokenHeader()` as a replacement. Note that you should use `PowerAuthTokenStore.generateAuthenticationHeader()` to make sure the PowerAuth SDK synchronize the time with the server properly.

  - `PowerAuthAuthorizationHttpHeader` is deprecated, use functions that provide `PowerAuthHttpHeader` instead.

  - `PowerAuthMissingConfigException` is removed. The configuration is validated in `PowerAuthConfiguration.Builder.build()` method.

  - `PowerAuthActivationStatus` is a new class that replaces `io.getlime.security.powerauth.core.ActivationStatus`. This change affects the following APIs:
    - `IActivationStatusListener` callback interface now gets `PowerAuthActivationStatus` in success.
    - `PowerAuthSDK.getLastFetchedActivationStatus()` now returns  `PowerAuthActivationStatus`.

  - `PowerAuthActivationState` is a new enumeration that replaces `io.getlime.security.powerauth.core.ActivationStatus.ActivationState`:
    - All new constants are uppercase as is usual in Java / Kotlin. For example `ActivationStatus.State_Pending_Commit` is now `PowerAuthActivationState.PENDING_COMMIT`.
    - There's no "CREATED" state due to fact that such state is never returned from the server.

- Changes in End-To-End encryption:
  - `PowerAuthSDK.getEciesEncryptorForApplicationScope()` - method is replaced with `getEncryptorForApplicationScope()` and provides `CoreEncryptor` object in case of success.
  - `PowerAuthSDK.getEciesEncryptorForActivationScope()` - method is replaced with `getEncryptorForActivationScope()` and provides `CoreEncryptor` object in case of success.
  - `IGetEciesEncryptorListener` is replaced with `IGetEncryptorListener`
  - `EciesEncryptor` is replaced with `CoreEncryptor`. The new class doesn't allow you to reuse its instance, so you have to create new encryptor for each encrypted request.
  - `EciesCryptogram` is replaced with `CoreEncryptedRequest`
  - `EciesMetadata` is no longer needed. All information required for request construction is now available in `CoreEncryptedRequest`.
  - `CoreEncryptedResponse` now represents an encrypted response received from the server.

- All methods in `Password` class now throws `IllegalStateException` when called on already destroyed object. In other words, if you call `destroy()` to force native C++ object cleanup, then the object is no longer available for use.

- The following classes and interfaces are now deprecated:
  - `IPersistActivationWithBiometricsListener` - use `IPersistActivationListener` instead.

- The following functions now takes or returns `SecureData` instead of `byte[]`:
  - `PowerAuthSDK.persistActivationWithPassword()`
  - `PowerAuthSDK.addBiometryFactor()`
  - `PowerAuthAuthentication.getBiometryFactorRelatedKey()`
  - `PowerAuthAuthentication.getOverriddenPossessionKey()`
  - All static functions in `PowerAuthAuthentication` that takes custom possession or biometry key in parameter.
  - `IFetchEncryptionKeyListener.onFetchEncryptionKeySucceed()`
  - `CryptoUtils.ecdhComputeSharedSecret()`
  - `BiometricKeyData.getDerivedData()`
  - `BiometricKeyData.getDataToSave()`

- Due to discontinued support for "External Encryption Key" feature, the following methods has been changed:
  - `PowerAuthSDK.setExternalEncryptionKey()` method has been removed.
  - `PowerAuthSDK.addExternalEncryptionKey()` method has been removed.
  - `PowerAuthSDK.removeExternalEncryptionKey()` method now takes EEK as parameter and allows you to remove the key from the activation.
  - `PowerAuthConfiguration.Builder.externalEncryptionKey()` property is deprecated and no longer used in SDK.
  - Check [External Encryption Key](PowerAuth-SDK-for-Android.md#external-encryption-key) documentation for the migration.

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

- Removed all interfaces deprecated in release `1.9.x`

### Other changes

- TBA

## iOS & tvOS

Notable changes on iOS:

- Added the `PowerAuthCoreData` object to `PowerAuthCore` module to enhance in-memory management of sensitive data.

### API changes

- The following methods or properties are now deprecated or changed:
  - `PowerAuthSDK` class:
    - class constructor taking only `PowerAuthConfiguration` object in parameter now **throws error**.
    - `unsafeChangePassword(from:to:)` - use new two-step API for password change `beginPasswordChange(oldPassword:callback:)` as a replacement.
    - `changePassword(from:to:callback:)` - use new two-step API for password change `beginPasswordChange(oldPassword:callback:)` as a replacement.
    - `validatePassword(password:callback:)` - method has no direct replacement. If your application requires password validation here, that indicates a deeper architectural issue that may introduce security vulnerabilities.
    - `persistActivation(with:)` - use asynchronous `persistActivation(with:callback:)` as a replacement.
    - `persistActivation(withPassword:)` - use asynchronous `persistActivation(withPassword:callback:)` as a replacement.
    - `removeBiometryFactor()` - use asynchronous `removeBiometryFactor(callback:)` as a replacement.
    - Constructor `PowerAuthSDK(configuration:keychainConfiguration:clientConfiguration:)` - use methods with `PowerAuthBiometricConfiguration` parameter instead.
    - `requestSignature(with:method:uriId:body:)` - use `authenticationHeaderForRequestWithBody(with:method:uriId:body:)` method instead.
    - `requestGetSignature(with:uriId:params:)` - use `authenticationHeaderForRequestWithParams(with:method:uriId:params:)` method with `"GET"` as method parameter.
    - `offlineSignature(with:uriId:body:nonce:)` - use asynchronous `offlineAuthenticationCode(with:uriId:body:nonce:callback:)` method that handle the biometric authentication properly.
    - `verifyServerSignedData(_:signature:masterKey:)` - use `verifyDigitalSignature(signature:forData:withKey:)` method where you can specify the key for verification.
    - `signData(withDevicePrivateKey:data:callback:)` - use `calculateDigitalSignature(authentication:forData:withKey:callback:)` method where you can specify the key for signing.
    - `signJwt(withDevicePrivateKey:claims:callback:)` - use `calculateJwsSignature(authentication:forData:dataType:compact:withKey:callback:)` method where you can specify the key for signing and format of token.
    - `createSignedCSR(with:distinguishedNames:subjectAltNames:callback)` - use `createCertificateSigningRequest(authentication:distinguishedNames:subjectAltNames:keyIdentifier:callback:)` method where you can specify the key to use for CSR creation.
    - `fetchEncryptionKey(_:index:callback:)` - method is effective only if PowerAuthSDK is running at protocol 3.3 and will be removed once we drop support for this legacy protocol. Meanwhile you can migrate to the new `fetchSecureVaultKey(authentication:keyIdentifier:callback:)` method providing a better flexibility for secure vault operations.

  - `PowerAuthConfiguration` class:
    - `offlineSignatureComponentLength` property is now replaced with `offlineAuthenticationCodeComponentLength`
    - `disableAutomaticProtocolUpgrade` property is deprecated and has no effect in SDK.
  - `PowerAuthTokenStore` protocol:
    - `generateAuthorizationHeader(withName:completion:)` is replaced with `generateAuthenticationHeader(withName:completion:)`
  - `PowerAuthAuthorizationHttpHeader` is deprecated and replaced with `PowerAuthHttpHeader`

- All static methods for accessing a various shared instances are now deprecated:
  - `PowerAuthSDK.initSharedInstance(...)` and `PowerAuthSDK.sharedInstance()` - To ensure better control and flexibility, manage the global instances within your application code.
  - `PowerAuthClientConfiguration.sharedInstance()` - use a class constructor with no parameters if you want to create the default configuration.
  - `PowerAuthKeychainConfiguration.sharedInstance()` - use a class constructor with no parameters if you want to create the default configuration.

- The following properties in `PowerAuthKeychainConfiguration` class are now deprecated:
  - `linkBiometricItemsToCurrentSet` - use new `PowerAuthBiometricConfiguration.invalidateBiometricFactorAfterChange` instead, with the same meaning.
  - `allowBiometricAuthenticationFallbackToDevicePasscode` - use new `PowerAuthBiometricConfiguration.allowFallbackToDevicePasscode` instead, with the same meaning.
  - `invalidateLocalAuthenticationContextAfterUse` - use new `PowerAuthBiometricConfiguration.invalidateLocalAuthenticationContextAfterUse` instead, with the same meaning.
  - Be aware that if you provide both, `PowerAuthBiometricConfiguration` and  `PowerAuthKeychainConfiguration` objects to initialize `PowerAuthSDK`, then the values from the biometric configuration takes precedence.

- `PowerAuthActivationState` enumeration no longer contains "created" case. The case is never returned from the server back to the mobile client.

- Changes in End-To-End encryption:
  - `PowerAuthSDK.eciesEncryptorForApplicationScope(callback:)` - method has been removed, use `encryptorForApplicationScope(callback:)` as replacement.
  - `PowerAuthSDK.eciesEncryptorForActivationScope(callback:)` - method has been removed, use `encryptorForActivationScope(callback:)` as replacement.
  - `PowerAuthCoreEciesEncryptor` class has been removed and replaced by `PowerAuthCoreEncryptor`. The new class doesn't allow you to reuse its instance, so you have to create new encryptor for each encrypted request.
  - `PowerAuthCoreEciesCryptogram` is removed and replaced by `PowerAuthCoreEncryptedRequest` and `PowerAuthCoreEncryptedResponse`.
  - `PowerAuthCoreEciesMetaData` is removed. You can get the encryption header in more straightforward way. Check the updated E2EE documentation for more details.

- The following functions or properties now takes or returns `PowerAuthCoreData` instead of `Data`:
  - `PowerAuthSDK.fetchEncryptionKey()`
  - All static functions in `PowerAuthAuthentication` that takes custom possession or biometry key in parameter.
  - `PowerAuthAuthentication.overridenPossessionKey` property is now `customPossessionKey`
  - `PowerAuthAuthentication.overridenBiometryKey` property is now `customBiometryKey`
  - `PowerAuthCoreCryptoUtils.ecdhComputeSharedSecret()`

- The following methods in `PowerAuthSDK` class now returns cancelable object allowing you to cancel the pending biometric authentication:
  - `authenticateUsingBiometry(withPrompt:callback:)`
  - `authenticateUsingBiometry(withContext:callback:)`

- Due to discontinued support for "External Encryption Key" feature, the following methods has been changed:
  - `PowerAuthSDK.setExternalEncryptionKey()` method has been removed.
  - `PowerAuthSDK.addExternalEncryptionKey()` method has been removed.
  - `PowerAuthSDK.removeExternalEncryptionKey()` method now takes EEK as parameter and allows you to remove the key from the activation.
  - `PowerAuthConfiguration.externalEncryptionKey` property is deprecated and no longer used in SDK.
  - Check [External Encryption Key](PowerAuth-SDK-for-iOS.md#external-encryption-key) documentation for the migration.

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

- Removed all interfaces deprecated in release `1.9.x`

- To support authenticated protocol upgrade, following method was added to the `PowerAuthSDK`:
  - `startProtocolUpgrade(password:callback:)`

### Other changes

- TBA

## iOS & tvOS App Extensions

- The `PowerAuth2ForExtensions` library is now deprecated and no longer supported and maintained. You can use full feature PowerAuth mobile SDK as a replacement in your app extension.

## Known Bugs

The PowerAuth SDKs for watchOS, do not use time synchronized with the server for token-based authentication. To avoid any compatibility issues with the server, the authentication headers generated in your App Extension or on watchOS still use the older protocol version 3.1. This issue will be fixed in a future SDK update.

You can watch the following related issues:

- [wultra/powerauth-mobile-sdk#551](https://github.com/wultra/powerauth-mobile-sdk/issues/551)
- [wultra/powerauth-mobile-watch-sdk#7](https://github.com/wultra/powerauth-mobile-watch-sdk/issues/7)