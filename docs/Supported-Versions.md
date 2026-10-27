# Supported Versions

We currently support the following versions of mobile OS:

- iOS 15.0
- tvOS: 15.0
- watchOS 9.0
- macOS Catalyst: 15.0
- Android 6.0 (API level 23)

## Feature Limitations

### Biometry Support

On iOS:

- The used biometric type depends on the particular device's capabilities.

On Android:

- Since Android 6.0, we have offered biometric authentication via fingerprint authentication support.
- Since Android 9.0, we have offered biometric authentication via the newly introduced unified biometric authentication dialog. However, we had to fallback to the old fingerprint authentication on several devices where the new biometric support was broken (as a well-known issue).
- PowerAuth requires a Class 3 (strong) biometric sensor. See the [Android biometric security documentation](https://source.android.com/docs/security/features/biometric) for details.
