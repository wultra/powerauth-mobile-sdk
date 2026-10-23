# PowerAuth Mobile SDK

Add bank-grade mobile security to your iOS, tvOS, watchOS and Android apps with the PowerAuth Mobile SDK. It is the client-side part of Wultra's [Mobile-First Authentication](https://www.wultra.com/products/mobile-first-authentication) and the [PowerAuth](https://www.wultra.com/product/powerauth-mobile-security-suite) platform. It takes care of the demanding network and cryptographic processes behind secure device activation, request signing and strong customer authentication, so you can ship a secure, frictionless user experience faster, with no need to build your own security layer.

## SDK Documentation

- [Android](PowerAuth-SDK-for-Android.md)
- [iOS and tvOS](PowerAuth-SDK-for-iOS.md)
- [watchOS](PowerAuth-SDK-for-watchOS.md)

## Tutorials

- [Upgrading to Post-Quantum Cryptography](Upgrading-to-Post-Quantum-Cryptography.md)

## Migration Guides

If you need to upgrade PowerAuth Mobile SDK to a newer version, you can check the following migration guides:

- [Migration from version `1.9.x` to `2.0.x`](Migration-from-1.9-to-2.0.md)
- [Migration from version `1.8.x` to `1.9.x`](Migration-from-1.8-to-1.9.md)
- [Migration from version `1.7.x` to `1.8.x`](Migration-from-1.7-to-1.8.md)
- [Migration from version `1.6.x` to `1.7.x`](Migration-from-1.6-to-1.7.md)
- [Older Migration Guides](Older-Migration-Guides.md)

## Cross Platform Support

- [PowerAuth Mobile JS SDK for React Native and Cordova](https://github.com/wultra/react-native-powerauth-mobile-sdk)
- [PowerAuth Mobile Flutter SDK](https://github.com/wultra/flutter-powerauth-mobile-sdk)

## Support and Compatibility

| Mobile SDK | Protocol         | PowerAuth Server              | Support Status                    |
|------------|------------------|-------------------------------|-----------------------------------|
| `2.0.x`    | `V4.0` or `V3.3` | `2.0+` or `1.9+`<sup>1</sup>  | Fully supported                   |
| `1.9.x`    | `V3.3`           | `1.9+`                        | Security & Functionality bugfixes |
| `1.8.x`    | `V3.2`           | `1.5+`                        | Security bugfixes                 |
| `1.7.x`    | `V3.1`           | `0.24+`                       | Security bugfixes                 |
| `1.6.x`    | `V3.1`           | `0.24+`                       | Not supported                     |

> **Note 1:** Protocol and server compatibility depend on the SDK configuration. If you choose to remain on protocol V3.3, PowerAuth Server version 1.9+ is required.

## License

All sources are licensed using Apache 2.0 license, you can use them with no restriction. If you are using PowerAuth 2.0, please let us know. We will be happy to share and promote your project.

## Contact

If you need any assistance, do not hesitate to drop us a line at [hello@wultra.com](mailto:hello@wultra.com).

### Security Disclosure

If you believe you have identified a security vulnerability with PowerAuth, you should report it as soon as possible via email to [support@wultra.com](mailto:support@wultra.com). Please do not post it to a public issue tracker.
