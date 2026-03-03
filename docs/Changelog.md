# Changelog

<!--------------------------------------------------->
## 2.0.0 (TBA - Not released yet)

### Important notice

- If you already using older versions of SDK, then please read our [Migration guide from 1.9.x to 2.0.x version](Migration-from-1.9-to-2.0)
- This version of SDK requires PowerAuth Server version `1.9.0` or `2.0.0` and newer, depending on PowerAuth Mobile SDK configuration. Check [Support and Compatibility](Readme.md#support-and-compatibility) for more details.

### Both platforms

- OpenSSL upgraded to version `3.5.5`
- PowerAuth protocol version 4.0 introduces major cryptographic upgrades to strengthen long-term security and add post-quantum protection. Signature and key agreement mechanisms now use larger elliptic curves (P-384) and optionally operate in hybrid mode with quantum-resistant ML-DSA and ML-KEM algorithms. The end-to-end encryption scheme transitions from ECIES with AES-128/CBC and HMAC-SHA-256 to an AEAD design using AES-256/CTR with KMAC-256, providing stronger integrity and confidentiality guarantees. Overall, version 4.0 modernizes the protocol to align with emerging cryptographic standards and resist future quantum attacks.
- Existing activations can be upgraded to the new PowerAuth protocol version 4.0 using the authenticated protocol upgrade procedure.
- You can select a level of security that suits your business needs. See the `PowerAuthConfiguration` documentation for more details.
- PowerAuth Mobile SDK can optionally operate in a mode fully compatible with legacy PowerAuth protocol version 3.3.
- A new `PowerAuthBiometricConfiguration` class simplifies biometric configuration of the `PowerAuthSDK` class.
- A new `PowerAuthSecureVaultKey` class provides better flexibility for Secure Vault operations.
- PowerAuth Mobile SDK now ensures sensitive keys are not retained in memory.
- Activation using a recovery code is no longer supported.
- External encryption key feature is discontinued and will be removed in the next SDK release.
- Custom possession factor key provided in `PowerAuthAuthentication` is no longer supported.

### Android

- NPE in BiometricAuthentication when keys invalidated by biometric enrollment ([795](https://github.com/wultra/powerauth-mobile-sdk/issues/795))
- Biometric authentication offloaded to the background thread ([677](https://github.com/wultra/powerauth-mobile-sdk/issues/677))

### Apple

- Hide symbols from transient dependencies ([688](https://github.com/wultra/powerauth-mobile-sdk/issues/688))


<!--------------------------------------------------->
## 1.9.6 (October 2025)

## Both platforms

- Added support for creating CRS signed with device private key ([707](https://github.com/wultra/powerauth-mobile-sdk/issues/707))

<!--------------------------------------------------->
## 1.9.5 (July 2025)

### Android

- Biometric authentication offloaded to the background thread ([677](https://github.com/wultra/powerauth-mobile-sdk/issues/677))
- ⚠️ **Important notice**
  Disable all interactive UI elements while biometric authentication is in progress. After you call `authenticateUsingBiometrics()`, display a non-interactive “Verifying…” (or similar) progress state and do not accept user input until the SDK callback fires.

  Why: Once the system biometric prompt is dismissed, your app regains focus before the PowerAuth SDK finishes its post-authentication cryptographic work on a background thread. During this brief window, your UI is visible but the authentication result is not ready. If you re-enable buttons or accept gestures too early, the user could trigger actions that assume authentication succeeded (or failed) prematurely. Wait for the callback, then update the UI based on the actual result. 


<!--------------------------------------------------->
## 1.9.4 (April 2025)

### Both platforms

- OpenSSL upgraded to version `3.4.1`

### Apple

- Fixed build problems on Xcode 16.3 ([689](https://github.com/wultra/powerauth-mobile-sdk/issues/689))
- Improved logging - check [documentation for details](PowerAuth-SDK-for-iOS.md#logs) (PR [685](https://github.com/wultra/powerauth-mobile-sdk/pull/685))

<!--------------------------------------------------->
## 1.9.3 (February 2025)

### Both platforms
 
- OpenSSL upgraded to version `3.4.0`

### Apple

- Added debug symbols to CocoaPods build ([667](https://github.com/wultra/powerauth-mobile-sdk/issues/667))

<!--------------------------------------------------->
## 1.9.2 (October 2024)

### Android

- Fixed temporary key expiration ([635](https://github.com/wultra/powerauth-mobile-sdk/issues/6635))

<!--------------------------------------------------->
## 1.9.1 (October 2024)

### Apple

- Fixed broken fetch for ECIES encryptor ([633](https://github.com/wultra/powerauth-mobile-sdk/issues/633))

<!--------------------------------------------------->
## 1.9.0 (October 2024)

- If you already using older versions of SDK, then please read our [Migration guide from 1.8.x to 1.9.x version](Migration-from-1.8-to-1.9)
- This version of SDK requires PowerAuth Server version `1.9.0` and newer. Check [Support and Compatibility](Readme.md#support-and-compatibility) for more details.

### Both platforms

- OpenSSL upgraded to version `1.1.1w`
- Support for PowerAuth protocol version 3.3 ([604](https://github.com/wultra/powerauth-mobile-sdk/issues/604))
- Support for new OIDC activation type ([619](https://github.com/wultra/powerauth-mobile-sdk/issues/619))

### Android

- Added support for devices with 16kB page size ([616](https://github.com/wultra/powerauth-mobile-sdk/issues/616))
- Biometric signatures no longer use the shared key ([620](https://github.com/wultra/powerauth-mobile-sdk/issues/620))
- Fixed JWT signature calculation ([614](https://github.com/wultra/powerauth-mobile-sdk/issues/614))

### Apple

- Fixed JWT signature calculation ([614](https://github.com/wultra/powerauth-mobile-sdk/issues/614))
