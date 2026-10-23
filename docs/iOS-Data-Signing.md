# Data Signing

<!-- SIDEBAR _Sidebar_iOS.md -->

The main feature of the PowerAuth protocol is data signing. PowerAuth has the following types of signatures:

- [Symmetric Multi-Factor Authentication Code](iOS-Authentication-Codes.md#symmetric-multi-factor-authentication-code): Suitable for most operations, such as login, new payment, or confirming changes in settings.
- [Symmetric Offline Multi-Factor authentication Code](iOS-Authentication-Codes.md#symmetric-offline-multi-factor-authentication-code): Suitable for very secure operations, where the authentication code is validated over the out-of-band channel.
- [Asymmetric Private Key Signature](iOS-Digital-Signatures.md#sign-data-with-device-private-key): Suitable for documents where a strong one-sided signature is desired.
- [Verify server signed data](iOS-Digital-Signatures.md#verify-server-signed-data): Suitable for receiving arbitrary data from the server.

## Read Next

- [Authentication Codes](iOS-Authentication-Codes.md)
