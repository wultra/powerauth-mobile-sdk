# Migration from 1.8.x to 1.9.x

PowerAuth Mobile SDK in version `1.9.0` provides the following improvements:

- Added support for PowerAuth protocol version 3.3, including the following improvements:
  - The PowerAuth protocol is no longer use EC key-pairs for encryption and signature calculation (dual use problem.)
  - The End-To-End encryption is now using a temporary keys to improve the forward secrecy of our ECIES scheme.
- Simplified construction of encrypted request and response. Check updated [Android](PowerAuth-SDK-for-Android.md#end-to-end-encryption) or [iOS](PowerAuth-SDK-for-iOS.md#end-to-end-encryption) documentation for more details.
- Now it's possible to create an activation via OpenID Connect provider.

### Compatibility with PowerAuth Server

- This release is fully compatible with PowerAuth Server version `1.9.0` and newer.

## Android

### API changes

- The following methods are no longer available in the `PowerAuthSDK` class:
  - Synchronous method `getEciesEncryptorForApplicationScope()` is replaced with asynchronous variant that guarantees the temporary encryption key is prepared.
  - Synchronous method `getEciesEncryptorForActivationScope()` is replaced with asynchronous variant that guarantees the temporary encryption key is prepared.

- The shared biometry-related encryption key is no longer supported in `PowerAuthSDK`. If an activation is already using the shared key, then it's in use until the activation or the biometry factor is removed. As part of this change, the following methods are now deprecated:
  - Method `PowerAuthSDK.removeActivationLocal(Context, boolean)` is now deprecated. Use `removeActivationLocal(Context)` as a replacement.
  - Method `PowerAuthKeychainConfiguration.getKeychainBiometryDefaultKey()` is now deprecated. Use `getKeychainKeyBiometry()` as a replacement.
  - Method `PowerAuthKeychainConfiguration.Builder.keychainBiometryDefaultKey(String)` is now deprecated. Use `keychainKeyBiometry(String)` as a replacement.
  
- Removed all interfaces deprecated in release `1.8.x`

### Other changes

#### End-To-End Encryption

Encrypted request now contains a new property `temporaryKeyId` with type `String`, please update your model objects. For example:

```json
{
  "temporaryKeyId" : "UUID",
  "ephemeralPublicKey" : "BASE64-DATA-BLOB",
  "encryptedData": "BASE64-DATA-BLOB",
  "mac" : "BASE64-DATA-BLOB",
  "nonce" : "BASE64-NONCE",
  "timestamp" : 1694172789256
}
```

You can use new `EciesCryptogram.toEncryptedRequest()` method to convert cryptogram into easily serializable request object. It's also no longer necessary to synchronize the time with the server, because as the new asynchronous `getEciesEncryptorFor{*}Scope()` methods do that automatically.

## iOS & tvOS

### API changes

- The following methods are no longer available in `PowerAuthSDK` class:
  - Synchronous function `eciesEncryptorForApplicationScope()` is replaced with asynchronous variant that guarantees the temporary encryption key is prepared.
  - Synchronous function `eciesEncryptorForActivationScope()` is replaced with asynchronous variant that guarantees the temporary encryption key is prepared.

- Removed all interfaces deprecated in release `1.8.x`

### Other changes

#### End-To-End Encryption

Encrypted request now contains a new property `temporaryKeyId` with type `String`, please update your model objects. For example:

```json
{
  "temporaryKeyId" : "UUID",
  "ephemeralPublicKey" : "BASE64-DATA-BLOB",
  "encryptedData": "BASE64-DATA-BLOB",
  "mac" : "BASE64-DATA-BLOB",
  "nonce" : "BASE64-NONCE",
  "timestamp" : 1694172789256
}
```

You can use the new `PowerAuthCoreEciesCryptogram.requestPayload()` function to prepare a dictionary containing all request parameters. It's also no longer necessary to synchronize the time with the server, because as the new asynchronous `eciesEncryptorFor{*}Scope()` functions do that automatically.

## iOS & tvOS App Extensions

- Removed all interfaces deprecated in release `1.8.x`

## Known Bugs

The PowerAuth SDKs for iOS and tvOS App Extensions, as well as for watchOS, do not use time synchronized with the server for token-based authentication. To avoid any compatibility issues with the server, the authentication headers generated in your App Extension or on watchOS still use the older protocol version 3.1. This issue will be fixed in a future SDK update.

You can watch the following related issues:

- [wultra/powerauth-mobile-sdk#551](https://github.com/wultra/powerauth-mobile-sdk/issues/551)
- [wultra/powerauth-mobile-watch-sdk#7](https://github.com/wultra/powerauth-mobile-watch-sdk/issues/7)
- [wultra/powerauth-mobile-extensions-sdk#7](https://github.com/wultra/powerauth-mobile-extensions-sdk/issues/7)