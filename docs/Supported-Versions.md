# Supported Versions

We currently support the following versions of mobile OS:

- iOS 11.0
- tvOS: 11.0
- watchOS 4.0
- macOS Catalyst: 10.15
- Android 5.0 (API level 21)

## Feature Limitations

### Biometry Support

On iOS:

- We offer the biometry support since iOS 9.0, the used biometric type depends on the particular device capabilities.

On Android:

- Since Android 6.0, we offer the biometric authentication via the fingerprint authentication support.
- Since Android 9.0, we offer the biometric authentication via the newly introduced unified biometric authentication dialog. However, we had to fallback to the old fingerprint authentication on several devices where the new biometric support is broken (as a well-known issue).
