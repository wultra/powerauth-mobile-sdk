# Troubleshooting

<!-- SIDEBAR _Sidebar.md -->

## tvOS support in CocoaPods

The tvOS SDK is not required by default since the SDK version 1.7.7. If your build or development machine doesn't have tvOS SDK installed, then the `PowerAuth2` module is precompiled with no tvOS platform included in the final xcframework. Since CocoaPods keep various build artifacts in its cache, then this might be problematic in case you'll add support for tvOS later, during the development. To fix such possible issues, please remove the `PowerAuth2` pod from the cache:

```sh
pod cache clean 'PowerAuth2' --all
```

## Length of application group

In case you use the [Activation data sharing](Share-Activation-Data.md) feature, the length of the application group encoded in UTF-8 must not exceed **26 characters**. This limitation exists because the feature relies on named shared memory objects, and iOS imposes an undocumented restriction on the length of such object names.

The total length is limited to 31 characters, but the shared memory object name must be prefixed with your app group, separated by a period (.), to function properly across your applications. We chose to use a 4-character long shared memory object name, generated from the PowerAuthSDK’s instance identifier. As a result, the actual limit for your app group name is:

```
31 - 1 - 4 = 26
```

You can extend the length of the application group slightly by providing your own `sharedMemoryIdentifier` in the `PowerAuthSharingConfiguration`. In theory, this allows you to use an app group name of up to 29 characters, leaving 1 character for the shared memory identifier. However, this is generally not recommended. A custom identifier should only be used if your application already employs shared memory and the SDK’s generated identifier conflicts with your existing shared memory objects.

## UserDefaults Migration

If your previous version of the application did not use shared data between the application and the extension, then you probably need to migrate the keychain status flag from `UserDefaults.standard` to a shared one. We recommend performing this migration at the main application's startup code and **BEFORE** the `PowerAuthSDK` object is configured and used:

```swift
private func migrateUserDefaults(appGroup: String) {
    guard let shared = UserDefaults(suiteName: appGroup) else {
        fatalError("AppGroup is not configured properly")
    }
    if shared.bool(forKey: PowerAuthKeychain_Initialized) {
        return // migration is not required
    }
    let standard = UserDefaults.standard
    if standard.bool(forKey: PowerAuthKeychain_Initialized) {
        standard.removeObject(forKey: PowerAuthKeychain_Initialized)
        standard.synchronize()
        shared.set(true, forKey: PowerAuthKeychain_Initialized)
        shared.synchronize()
    }
}
```

## Upgrade from older SDKs

PowerAuth Mobile SDK version `2.0.0` introduced a new internal activation data format that is incompatible with previous SDK versions. This change is particularly important if you are using the [Activation Data Sharing](Share-Activation-Data.md) feature to share activation data between multiple applications. In such a setup, you may encounter a situation where one of your applications is already upgraded to a newer SDK version and the modified data is not recognized by an application using an older SDK version. This situation may lead to unexpected removal of activation data.

To prevent this, it is very important to carefully plan how you roll out application updates to your users. It is recommended to follow these steps to reliably upgrade your applications to PowerAuth SDK 2.0 (and later):

1. First, upgrade all your applications to SDK 2.0+ and set the [algorithm](Configuration.md#algorithms-for-communication) to `LEGACY_P256`. In this setup, the activation data format remains fully compatible with older SDK versions.
2. Wait until a significant portion of your users are using version `2.0+` across all your applications.
3. Then switch the [algorithm](Configuration.md#algorithms-for-communication) to the one you intend to use going forward (for example, `EC_P384_ML_L3`).

<!-- begin box info -->
The procedure above is not required if you are using activation data sharing to share data between a single application and its extensions. This setup is safe because the extensions are part of the main application and are upgraded at the same time.
<!-- end -->

## Read Next

- [PowerAuth Mobile SDK for iOS and tvOS Apps](../PowerAuth-SDK-for-iOS.md)
