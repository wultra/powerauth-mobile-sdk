# Migration from 1.2.x to 1.3.x

This guide contains instructions for migration from PowerAuth Mobile SDK version `1.2.x` to version `1.3.x`.

## Introduction

PowerAuth Mobile SDK in version `1.3.0` introduces support for latest PowerAuth protocol version `3.1`. The main changes in PowerAuth protocol are following:

- Improved information entropy in PowerAuth online signatures. The signature is now encoded into BASE64 instead of decimal string.
- Improved protection of encrypted status blob against possible replay attacks.
- Improved protection of payload encrypted by our ECIES scheme.
- Improved protocol reliability. The mobile client is now able to synchronize its signature counter with the server's.

The changes of cryptography are documented in details in the [powerauth-crypto](https://github.com/wultra/powerauth-crypto) project.


### Compatibility with PowerAuth Server

- This release is fully compatible with PowerAuth Server version `0.23.x`.

### Important

- Please be aware that PowerAuth mobile SDK `1.3.4` fixed a [serious issue with protocol upgrade](https://github.com/wultra/powerauth-mobile-sdk/issues/302) from `V2.x` to `V3.1`. You should upgrade your application to `1.3.4` and newer. 

## Android

### API changes

- Added a new activation state `ActivationStatus.State_Deadlock`.
  - This new state indicates that local activation is technically blocked and no longer can be used for the signature calculations.
  - The application should handle this situation in the following steps:
    1. Inform user that activation is no longer available
    2. Remove the local activation, by calling:
       ```java
       powerAuthSDK.removeActivationLocal(context);
       ```
  - For more details, please check [issue #236](https://github.com/wultra/powerauth-mobile-sdk/issues/236).

## iOS

### API changes

- Added a new activation state `PA2ActivationState_Deadlock`
  - This new state indicates that local activation is technically blocked and no longer can be used for the signature calculations.
  - The application should handle this situation in the following steps:
    1. Inform user that activation is no longer available
    2. Remove the local activation, by calling:
       ```swift
       PowerAuthSDK.sharedInstance().removeActivationLocal();
       ```
  - For more details, please check [issue #236](https://github.com/wultra/powerauth-mobile-sdk/issues/236).
