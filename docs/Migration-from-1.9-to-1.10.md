# Migration from 1.9.x to 1.10.x

PowerAuth Mobile SDK in version `1.10.0` provides the following improvements:

- Removed support of activation by recovery code.


### Compatibility with PowerAuth Server

- This release is fully compatible with PowerAuth Server version `1.9.0` and newer.

## Android

### API changes

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

### API changes

- Due to removed support of recovery codes, the following classes and methods are no longer available:
  - Methods removed in `PowerAuthSDK`:
    - `createActivation(withName:, recoveryCode:, recoveryPuk:, extras:, callback:)`
    - `hasActivationRecoveryData()`
    - `activationRecoveryData(authentication:, callback:)`
    - `confirm(recoveryCode:, authentication:, callback:)`
  - Methods removed in `PowerAuthActivationCodeUtil`:
    - `validateRecoveryCode()`
    - `validateRecoveryPuk()`
    - `parseFromRecoveryCode()`
  - Other changes:
    - removed class `PowerAuthActivationRecoveryData`
    - removed property `PowerAuthActivationResult.activationRecovery`
    - removed constructor `PowerAuthActivation(recoveryCode:, recoveryPuk:, name:)`

- Removed all interfaces deprecated in release `1.9.x`

### Other changes

- TBA

## iOS & tvOS App Extensions

- Removed all interfaces deprecated in release `1.9.x`

## Known Bugs

The PowerAuth SDKs for iOS and tvOS App Extensions, as well as for watchOS, do not use time synchronized with the server for token-based authentication. To avoid any compatibility issues with the server, the authentication headers generated in your App Extension or on watchOS still use the older protocol version 3.1. This issue will be fixed in a future SDK update.

You can watch the following related issues:

- [wultra/powerauth-mobile-sdk#551](https://github.com/wultra/powerauth-mobile-sdk/issues/551)
- [wultra/powerauth-mobile-watch-sdk#7](https://github.com/wultra/powerauth-mobile-watch-sdk/issues/7)
- [wultra/powerauth-mobile-extensions-sdk#7](https://github.com/wultra/powerauth-mobile-extensions-sdk/issues/7)