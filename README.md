# PowerAuth Mobile SDK

To connect to the [PowerAuth](https://www.wultra.com/product/powerauth-mobile-security-suite) service, mobile applications need to perform the required network and cryptographic processes, as described in the PowerAuth documentation. To simplify the implementation of these processes, developers can use iOS and Android libraries from this repository.

## Integration Tutorials

- [PowerAuth SDK for iOS and tvOS Apps](./docs/PowerAuth-SDK-for-iOS.md)
- [PowerAuth SDK for watchOS](./docs/PowerAuth-SDK-for-watchOS.md)
- [PowerAuth SDK for Android Apps](./docs/PowerAuth-SDK-for-Android.md)

Related projects

- [PowerAuth SDK for React Native](https://github.com/wultra/react-native-powerauth-mobile-sdk)

## Migration guides

If you need to upgrade PowerAuth Mobile SDK to a newer version, you can check following migration guides:

- [Migration from version `1.9.x` to `2.0.x`](docs/Migration-from-1.9-to-2.0.md)
- [Migration from version `1.8.x` to `1.9.x`](docs/Migration-from-1.8-to-1.9.md)
- [Migration from version `1.7.x` to `1.8.x`](docs/Migration-from-1.7-to-1.8.md)
- [Migration from version `1.6.x` to `1.7.x`](docs/Migration-from-1.6-to-1.7.md)
- [Older Migration Guides](docs/Older-Migration-Guides.md)

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