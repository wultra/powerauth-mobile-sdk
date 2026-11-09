# Migration from 2.0.x to 2.1.x

PowerAuth Mobile SDK in version `2.1.0` provides the following improvements:

- Activation status now includes the optional expiration time of a temporary activation block.
- Minimum deployment targets on Apple platforms are raised to support Xcode 27.

### Compatibility with PowerAuth Server

- This release is fully compatible with PowerAuth Server version `2.0.0` and later.
- If you configure `PowerAuthSDK` to operate with the legacy PowerAuth protocol 3.3, it requires PowerAuth Server version `1.9.0` or later.
- The temporary activation block expiration time requires PowerAuth Server version `2.2.0` or later. With older versions, or with protocol 3.3, the value is always `null`.

## Android

Notable changes on Android:

- There's no specific change on Android platform.

### API changes

- The following methods or properties are new:
  - `PowerAuthActivationStatus` class:
    - `getBlockExpirationTime()` - returns the time when a temporarily blocked activation will be unblocked, otherwise `null`. To compare the value with the current time, use `IPowerAuthTimeSynchronizationService`.

### Other changes

- There are no other changes on Android platform.

## iOS & tvOS

Notable changes on iOS:

- Minimum deployment targets are raised to iOS `15.0`, tvOS `15.0` and macOS Catalyst `15.0` to support Xcode 27.

### API changes

- The following methods or properties are new:
  - `PowerAuthActivationStatus` class:
    - `blockExpirationTime` - contains the time when a temporarily blocked activation will be unblocked, otherwise `nil`. To compare the value with the current time, use `PowerAuthTimeSynchronizationService`.

### Other changes

- There are no other changes on iOS & tvOS platforms.

## watchOS

Notable changes on watchOS:

- Minimum deployment target is raised to watchOS `9.0` to support Xcode 27.

### API changes

- There are no API changes on watchOS platform.
