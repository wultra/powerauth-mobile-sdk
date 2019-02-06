# Migration from 0.20.x to 1.0.0

This guide contains instructions for migration from PowerAuth Mobile SDK version 0.20.x to version 1.0.0.

## Introduction

In PowerAuth Release `2018.12`, we have introduced a few cryptographic improvements in PowerAuth protocol, which unfortunately led to few API breaking changes. We're calling all this changes in our documentation as "Crypto 3.0", or "PowerAuth protocol V3". Similarly, the old, legacy crypto, is now called as "PowerAuth protocol V2". Unfortunately, all this means that "V3" clients, cannot work with "V2" servers. So, we need to keep, for a limited time, two separate versions of SDK:

- PowerAuth Mobile SDK 0.20.x (in git branch `release/0.20.x`) is now a legacy version of SDK, based on PowerAuth protocol V2 and can cooperate with "V2" and "V3" servers. We will provide only a limited support for this branch of SDK. That means that we will fix only a critical or a security issues.
- PowerAuth Mobile SDK 1.0.x is now a main, fully supported branch of SDK, which can cooperate with "V3" servers only.

Fortunately, we have achieved that those both versions are API compatible, as much as possible. So, if you already migrated to version `0.20.0`, then the migration to `1.0.0` should be a quite easy now. Check [Migration from 0.19.0 to 0.20.0](./Migration-from-0.19-to-0.20.md) for more details.

## Android

### API changes

- Minimum API level is now 16

- Removed following constants from `PowerAuthErrorCodes` class: 
  - `PA2ErrorCodeAuthenticationFailed` removed (unused)
  - `PA2ErrorCodeKeychain` removed (unused)
  - `PA2ErrorCodeTouchIDNotAvailable` removed (unused) 
  - `PA2ErrorCodeTouchIDCancel` is now replaced with `PA2ErrorCodeBiometryCancel`

- We have removed all interfaces related to our "V2" E2E encryption (e.g. classes like `Encryptor`, `PA2EncryptorFactory`...). You can now use following interfaces as a replacement:
  - `EciesEncryptor` as a common object for custom request encryption and decryption. You can acquire a right encryptor object from `PowerAuthSDK` instance. Check [SDK documentation for details](./PowerAuth-SDK-for-Android.md#end-to-end-encryption).
  - `EciesCryptogram` is now a common representation for encrypted request and response.

- We have changed interface for custom activations, which is now much simpler. The custom activation is now fully supported in SDK, so you don't need to provide a custom URL, or other parameters.
  - Use new `PowerAuthSDK.createCustomActivation(...)` method

- We have added a several annotations to our API, that may lead to several warnings, if you mis-use our interfaces:
  - Usage of integer constant from `PowerAuthErrorCodes`, is now marked with with `@PowerAuthErrorCodes` annotation
  - Usage of integer constant from `ErrorCode` (low level APIs), is now marked with `@ErrorCode` annotation
  - All callbacks from `PowerAuthSDK` class are now returned to the main thread (`@MainThread` annotation)
  - Added nullability attributes to more interfaces.

- You should handle following new error constants in your application:
  - `PA2ErrorCodeProtocolUpgrade` - unrecoverable protocol upgrade error
  - `PA2ErrorCodePendingProtocolUpgrade` - operation is temporarily unavailable due to protocol upgrade.
  - Check [Error handling](./PowerAuth-SDK-for-Android.md#error-handling) for more details

## iOS

### API changes

- Removed following unused constants:
  - `PA2ErrorCodeAuthenticationFailed` removed (unused)
  - `PA2ErrorCodeKeychain` removed (unused)

- We have removed all interfaces related to our "V2" E2E encryption (e.g. classes like `PA2EncryptorFactory`). You can now use following interfaces as a replacement:
  - `PA2ECIESEncryptor` as a common object for custom request encryption and decryption. You can acquire a right encryptor object from `PowerAuthSDK` instance. Check [SDK documentation for details](./PowerAuth-SDK-for-iOS.md#end-to-end-encryption).
  - `PA2ECIESCryptogram` is now a common representation for encrypted request and response.

- We have changed interface for custom activations, which is now much simpler. The custom activation is now fully supported in SDK, so you don't need to provide a custom URL, or other parameters.
  - Use a new method:
    ```objc
    - (nullable id<PA2OperationTask>) createActivationWithName:(nullable NSString*)name
                                            identityAttributes:(nonnull NSDictionary<NSString*,NSString*>*)identityAttributes
                                                        extras:(nullable NSString*)extras
                                                      callback:(nonnull void(^)(PA2ActivationResult * _Nullable result, NSError * _Nullable error))callback;
    ```

- `PA2OperationTask` is now a protocol instead of class. This change should not have an implications to your code, unless you accessed properties from previous object implementation.

- You should handle following new error constants in your application:
  - `PA2ErrorCodeProtocolUpgrade` - unrecoverable protocol upgrade error
  - `PA2ErrorCodePendingProtocolUpgrade` - operation is temporarily unavailable due to protocol upgrade.
  - Check [Error handling](./PowerAuth-SDK-for-iOS.md#error-handling) for more details