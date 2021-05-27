# Migration from 1.0.x to 1.1.x

PowerAuth Mobile SDK in version `1.1.0` doesn't require any specific migration steps. This release contains the following changes:

- Adds support for [Recovery Codes](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Activation-Recovery.md) feature.
- Deprecates classes related to password strength testing (`PasswordUtil` and `PA2PasswordUtil`)

### Compatibility with PowerAuth Server

- This release is fully compatible with PowerAuth Server version `0.22.x`.
- If your application doesn't use Recovery Codes, then you can use this SDK also against `0.21.x` servers.

## Android

### API changes

- `PasswordUtil` class is now deprecated. You can use our [Passphrase Meter](https://github.com/wultra/passphrase-meter) library as a replacement.
- Added methods validating Recovery Codes to `PA2OtpUtil`
  - `PA2OtpUtil.validateRecoveryCode(...)`
  - `PA2OtpUtil.validateRecoveryPuk(...)`
  - `PA2OtpUtil.parseFromRecoveryCode(...)`
- Added methods related to Recovery Codes feature to `PowerAuthSDK`
  - `PowerAuthSDK.createActivation(withName:, recoveryCode:, puk:, ...)`
  - `PowerAuthSDK.hasActivationRecoveryData()`
  - `PowerAuthSDK.activationRecoveryData(...)`
  - `PowerAuthSDK.confirmRecoveryCode(...)`
- Class `CreateActivationResult` has new `getRecoveryData()` method, returning `RecoveryData` object, during the activation.
- Added `PA2Log.setVerbose(boolean)` to turn-on additional debug logs

## iOS

### API changes

- `PA2PasswordUtil` is now deprecated. You can use our [Passphrase Meter](https://github.com/wultra/passphrase-meter) library as a replacement.
- Added methods validating Recovery Codes to `OtpUtil`
  - `OtpUtil.validateRecoveryCode(...)`
  - `OtpUtil.validateRecoveryPuk(...)`
  - `OtpUtil.parseFromRecoveryCode(...)`
- Added methods related to Recovery Codes feature to `PowerAuthSDK`
  - `PowerAuthSDK.createRecoveryActivation(...)`
  - `PowerAuthSDK.hasActivationRecoveryData()`
  - `PowerAuthSDK.getActivationRecoveryData(...)`
  - `PowerAuthSDK.confirmRecoveryCode(...)`
- Class `PA2ActivationResult` has new `activationRecovery` property, containing `PA2ActivationRecoveryData` object, during the activation.
- Added `PA2LogSetVerbose(bool)` to turn-on additional debug logs
