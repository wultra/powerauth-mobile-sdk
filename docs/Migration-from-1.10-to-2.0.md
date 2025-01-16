# Migration from 1.10.x to 2.0.x

PowerAuth Mobile SDK in version `2.0.0` provides the following improvements:

- TBA

### Compatibility with PowerAuth Server

- This release is fully compatible with PowerAuth Server version `2.0.0` and newer.

## Android

### API changes

- Removed all interfaces deprecated in release `1.10.x`

### Other changes

- TBA

## iOS & tvOS

### API changes

- Removed all interfaces deprecated in release `1.10.x`

### Other changes

- TBA

## iOS & tvOS App Extensions

- Removed all interfaces deprecated in release `1.10.x`

## Known Bugs

The PowerAuth SDKs for iOS and tvOS App Extensions, as well as for watchOS, do not use time synchronized with the server for token-based authentication. To avoid any compatibility issues with the server, the authentication headers generated in your App Extension or on watchOS still use the older protocol version 3.1. This issue will be fixed in a future SDK update.

You can watch the following related issues:

- [wultra/powerauth-mobile-sdk#551](https://github.com/wultra/powerauth-mobile-sdk/issues/551)
- [wultra/powerauth-mobile-watch-sdk#7](https://github.com/wultra/powerauth-mobile-watch-sdk/issues/7)
- [wultra/powerauth-mobile-extensions-sdk#7](https://github.com/wultra/powerauth-mobile-extensions-sdk/issues/7)