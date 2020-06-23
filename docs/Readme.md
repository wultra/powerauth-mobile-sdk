# PowerAuth Mobile SDK

In order to connect to the [PowerAuth](https://www.wultra.com/product/powerauth-mobile-security-suite) service, mobile applications need to perform the required network and cryptographic processes, as described in the PowerAuth documentation. To simplify implementation of these processes, developers can use iOS and Android libraries from this repository.

## Integration Tutorials

- [PowerAuth SDK for iOS Apps](PowerAuth-SDK-for-iOS.md)
- [PowerAuth SDK for iOS Extensions](PowerAuth-SDK-for-iOS-Extensions.md)
- [PowerAuth SDK for watchOS](PowerAuth-SDK-for-watchOS.md)
- [PowerAuth SDK for Android Apps](PowerAuth-SDK-for-Android.md)

## Support and Compatibility

| Mobile SDK | Protocol | PowerAuth Server    | Support Status                    |
|------------|----------|---------------------|-----------------------------------|
| `1.4.x`    | `V3.1`   | `0.24+`             | Fully supported                   |
| `1.3.x`    | `V3.1`   | `0.23+`             | Security & Functionality bugfixes |
| `1.2.x`    | `V3.0`   | `0.22+`<sup>2</sup> | Security bugfixes                 |
| `1.1.x`    | `V3.0`   | `0.21+`             | Security bugfixes                 |
| `0.20.x`   | `V2.1`   | `0.18+`             | Security bugfixes                 |

> Notes
> 1. If [Recovery Codes](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Activation-Recovery.md) feature is not used, then you can
>    use this version also with PowerAuth Server `0.21`.

## Migration guides

If you need to upgrade PowerAuth Mobile SDK to a newer version, you can check following migration guides:

- [Migration from version `1.3.x` to `1.4.x`](Migration-from-1.3-to-1.4.md)
- [Migration from version `1.2.x` to `1.3.x`](Migration-from-1.2-to-1.3.md)
- [Migration from version `1.1.x` to `1.2.x`](Migration-from-1.1-to-1.2.md)
- [Migration from version `1.0.x` to `1.1.x`](Migration-from-1.0-to-1.1.md)
- [Migration from version `0.20.x` to `1.0.x`](Migration-from-0.20-to-1.0.md)
- [Migration from version `0.19.x` to `0.20.x`](Migration-from-0.19-to-0.20.md)

## License

All sources are licensed using Apache 2.0 license, you can use them with no restriction. If you are using PowerAuth 2.0, please let us know. We will be happy to share and promote your project.

## Contact

If you need any assistance, do not hesitate to drop us a line at [hello@wultra.com](mailto:hello@wultra.com).

### Security Disclosure

If you believe you have identified a security vulnerability with PowerAuth, you should report it as soon as possible via email to [support@wultra.com](mailto:support@wultra.com). Please do not post it to a public issue tracker.
