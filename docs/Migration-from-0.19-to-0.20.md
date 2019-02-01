# Migration from 0.19.x to 0.20.x

This guide contains instructions for migration from PowerAuth Mobile SDK version `0.19.x` to version `0.20.0`.

## Introduction

In PowerAuth Release `2018.12`, we have introduced a few cryprographic improvements in PowerAuth procotol, which unfortunately leads to few API breaking changes. We're calling all this changes in our documentation as "Crypto 3.0", or "PowerAuth protocol V3". Similarly, the old, legacy crypto, is now called as "PowerAuth protocol V2". Unfortunately, all this means that "V3" clients, cannot work with "V2" servers. So, we need to keep, for a limited time, two separate versions of SDK:

- PowerAuth Mobile SDK 0.20.x (in git branch `release/0.20.x`) is now a legacy version of SDK, based on PowerAuth protocol V2 and can cooperate with both, "V2" and "V3" servers. We will provide only a limited support for this branch of SDK. That means that we will fix only a critical or a security issues in this version of SDK.
- PowerAuth Mobile SDK 1.0.x is now a main, fully supported branch of SDK, which can cooperate with "V3" servers only.

Fortunately, we have achieved that those both versions are API compatible, as much as possible. That means that if you upgrade to `0.20.0` now, then you'll have less issues with migration to `1.0.0` once your server gets update to "V3" protocol. 

## Android API changes

- `PowerAuthAuthorizationHttpHeader` is now located at `io.getlime.security.powerauth.sdk` package. You need to update your imports by remove `.impl` part from import path.

- `AsyncTask` is no longer returned from asynchronous SDK methods. We're using a custom `ICancelable` interface from `io.getlime.security.powerauth.networking.interfaces` package as a replacement.

- Following constants from `PowerAuthErrorCodes` class are now deprecated (will be removed in `1.0`): 
  - `PA2ErrorCodeAuthenticationFailed`
  - `PA2ErrorCodeKeychain`
  - `PA2ErrorCodeTouchIDNotAvailable` 
  - `PA2ErrorCodeTouchIDCancel` deprecated and replaced with `PA2ErrorCodeBiometryCancel`

## iOS API changes

- All asycnhronous APIs now returns nullable `PA2OperationTask`. If `nil` is returned, then the asynchronous operation was not started properly. That may typically happen when you provide for example invalid parameters to the function. So, it's no longer required to check `task.isCancelled` to check whether the operation is properly started.

- Following constants are now deprecated:
  - `PA2ErrorCodeAuthenticationFailed` removed (unused)
  - `PA2ErrorCodeKeychain` removed (unused)