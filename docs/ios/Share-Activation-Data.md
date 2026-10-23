# Share Activation Data

<!-- SIDEBAR _Sidebar.md -->

This chapter explains how to share the `PowerAuthSDK` activation state between application and its extensions, or between multiple applications from the same vendor.

<!-- begin box warning -->
This feature is not supported on the macOS Catalyst platform.
<!-- end -->

<!-- begin box warning -->
If you used this feature in an SDK version older than 2.0.0, please read the [Upgrade from older SDKs](Troubleshooting.md#upgrade-from-older-sdks) chapter first.
<!-- end -->

## Prepare Activation Data Sharing

The App Extension normally doesn't have access to data created by the main application, so the first step is to set up data sharing for your project.

### Keychain Sharing

iOS SDK stores its most sensitive data into the iOS keychain, so you need to configure the keychain sharing first. If you're not familiar with keychain sharing, then don't worry about that, the keychain is shared only between the vendor's applications. So the sensitive information is not exposed to 3rd party applications.

1. Select your application project in the **Project Navigator** to navigate to the target configuration window and select the applications's target under the **TARGETS** heading in the sidebar.
2. Now select **Signing & Capabilities** tab and click **+ Capability** button.
3. Find and add **Keychain Sharing** capability.
4. Click "+" in just created **Keychain Sharing** capability and Xcode will predefine first **Keychain Group** to your application's bundle name. Let's call this value as `KEYCHAIN_GROUP_NAME`

<!-- begin box info -->
The predefined group is usually beneficial because iOS is by default using that group for storing all keychain entries created in the application. So, If your application is already using PowerAuth and you're going to just add extension support, then this is the most simple way to set up a keychain sharing.
<!-- end -->

Now you have to do a similar setup for your application's extension:

5. Select your application project in the **Project Navigator** to navigate to the target configuration window and select the extensions's target under the **TARGETS** heading in the sidebar.
6. Select **Signing & Capabilities** tab and click **+ Capability** button.
7. Find and add **Keychain Sharing** capability.
8. Click "+" in just created **Keychain Sharing** capability and add the same `KEYCHAIN_GROUP_NAME` as you did for the application's target.
9. (optional) Repeat steps 4 to 6 for all other extensions which supposed to use shared activation data.

Now you need to know your **Team ID** (the unique identifier assigned to your team by Apple). Unfortunately, the identifier is not simply visible in Xcode, so you'll have to log in to Apple's [development portal](http://developer.apple.com/account) and look for that identifier on your membership details page.

If you know the Team ID, then the final `KEYCHAIN_GROUP_IDENTIFIER` constant is composed as `TEAM_ID.KEYCHAIN_GROUP_NAME`. So, it should look like: `KTT00000MR.com.powerauth.demo.App`.

### App Groups

The PowerAuth SDK for iOS is using one boolean flag stored in the `UserDefaults` facility, to determine whether the application has been reinstalled. Unfortunately, the `UserDefaults.standard` created by the application cannot be shared with the app extension, so you have to create a new application group to share that data.

1. Select your application project in the **Project Navigator** to navigate to the target configuration window and select the applications's target under the **TARGETS** heading in the sidebar.
2. Now select **Signing & Capabilities** tab and click **+ Capability** button.
3. Find and add **App Groups** capability.
3. Click "+" in just created **App Groups** capability add a group with the desired identifier and turn this particular group ON (e.g. make sure that the checkmark close to the group's name is selected). Let's call this value `APP_GROUP_IDENTIFIER`. If the group already exists, then just click the checkmark to turn it ON.
4. Now switch to the application's extension target, select the **Capabilities** tab, and also expand the **App Groups** section.
5. Turn "ON" **App Groups** for extension and add an app group with the same name as you did in step 3.

You can optionally check a troubleshooting section if you need to [migrate the keychain initialization flag](Troubleshooting.md#userdefaults-migration) from standard user defaults to a shared one.

## Configure Activation Data Sharing

To share the activation's state just assign an instance of the `PowerAuthSharingConfiguration` object into `PowerAuthConfiguration`:

```swift
// Keychain sharing and App Group constants
let keychainSharing = "KTT00000MR.com.powerauth.demo.App"   // KEYCHAIN_GROUP_IDENTIFIER constant
let appGroup = "group.your.app.group"                       // APP_GROUP_IDENTIFIER constant
// Prepare the configuration
let configuration = PowerAuthConfiguration(
        instanceId: Bundle.main.bundleIdentifier!,
        baseEndpointUrl: "https://<your-domain>/enrollment-server",
        configuration: "ARDDj6EB6iAUtNm...KKEcBxbnH9bMk8Ju3K1wmjbA==")
// Assign sharing configuration
configuration.sharingConfiguration = PowerAuthSharingConfiguration(
    appGroup: appGroup,
    appIdentifier: "com.powerauth.demo.App", 
    keychainAccessGroup: keychainSharing)

// Create a PowerAuthSDK instance
let powerAuthSDK = try PowerAuthSDK(configuration: configuration)
```

The `PowerAuthSharingConfiguration` object contains the following properties:

- `appGroup` is the name of the app group shared between your applications. Be aware, that the length of app group encoded in UTF-8, should not exceed 26 characters. See [troubleshooting](Troubleshooting.md#length-of-application-group) section for more details.
- `appIdentifier` is an identifier unique across all your applications or extensions that are supposed to use the shared activation data. You can use your applications' bundle identifiers or any other identifier that can be then identified in all your applications (such as `smartBank`, `smartBank.walletExt`, `investmentsApp`, etc.) Due to technical limitations, the length of the identifier must not exceed 127 bytes, if represented in UTF-8.
- `keychainAccessGroup` is an access group for keychain sharing.

<!-- begin box info -->
Unlike the regular configuration the `instanceId` value in `PowerAuthConfiguration` should not be derived on the application's bundle identifier. This is because all applications and extensions that share PowerAuth data must use the same identifier. To ensure consistency, use a predefined constant string or an identifier based on the first application that integrated PowerAuth. This guarantees that all related components can access the same PowerAuth instance without conflicts.
<!-- end -->

<!-- begin box warning -->
It is also strongly recommended not to use the same `appIdentifier` for more than one instance of `PowerAuthSDK` running in the same application or extension (i.e. do not share the data between multiple instances running in the same process).
<!-- end -->

## External pending operations

Some operations, such as the activation process, must be exclusively finished in the application that initiated the operation. For example, if you start an activation process in one app, then all other applications that use the same shared activation data may receive a failure with the `PowerAuthErrorCode.externalPendingOperation` error code until the operation is finished. To prevent such errors you can determine this state in advance:

```swift
if let externalOperation = powerAuthSDK.externalPendingOperation {
    print("Application \(externalOperation.externalApplicationId) already started \(externalOperation.externalOperationType)")
}
```

The same `PowerAuthExternalPendingOperation` object can be also extracted from the `NSError` error. For example:

```swift
powerAuthSDK.createActivation(activation) { (result, error) in
    if let error = error {
        if let externalOperation = error.powerAuthExternalPendingOperation {
            print("Application \(externalOperation.externalApplicationId) already started \(externalOperation.externalOperationType)")
        }
    }
}
```

## Read Next

- [Synchronized Time](Synchronized-Time.md)
