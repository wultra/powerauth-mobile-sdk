# Migration from 1.3.x to 1.4.x

This guide contains instructions for migration from PowerAuth Mobile SDK version `1.3.x` to version `1.4.x`.

## Introduction

PowerAuth Mobile SDK in version `1.4.0` introduces support for an [additional activation OTP](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Additional-Activation-OTP.md) feature.

### Compatibility with PowerAuth Server

- This release is fully compatible with PowerAuth Server version `0.24.x`.

## Android

### API changes

- Added a new `PowerAuthActivation` class that unifies an activation creation process. Use new simple `PowerAuthSDK.createActivation(activation, listener)` method to create an activation.
  - This change doesn't break your existing code. We still maintain an old way of the activation creation, but don't hesitate to try this new approach. 
  

## iOS

### API changes

- Added a new `PowerAuthActivation` class that unifies an activation creation process. Use new simple `PowerAuthSDK.createActivation(activation) { .. } ` method to create an activation.
  - This change doesn't break your existing code. We still maintain an old way of the activation creation, but don't hesitate to try this new approach. 