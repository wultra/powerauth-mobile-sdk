# Biometry Setup

<!-- SIDEBAR _Sidebar.md -->

PowerAuth SDK for iOS provides an abstraction on top of the base Touch and Face ID support. While the authentication / data signing itself is nicely and transparently embedded in the `PowerAuthAuthentication` object used in [regular request signing](Data-Signing.md), other biometry-related processes require their own API. This part of the documentation is not relevant to the **tvOS** platform.

## Check Biometry Status

You have to check for biometry on three levels:

- **System Availability**: If Touch ID or Face ID is present on the system.
- **Activation Availability**: If biometry factor data are available for given activation.
- **Application Availability**: If the user decides to use Touch ID for a given app. _(optional)_

PowerAuth SDK for iOS provides code for the first two of these checks.

### Overall Status

To get information on whether biometric authentication is fully available, you can use the following code:

```swift
if powerAuthSDK.isAuthenticationWithBiometricsAvailable {
    // Biometric authentication is available, you can construct PowerAuthAuthentication with biometry 
} else {
    // Fallback to PIN
}
```

The function returns `true` only if activation has biometry factor-related data available and the device has a biometric sensor available and biometrics are enrolled in the system.

To get more detailed information, use the following code:

```swift
let biometricStatus = powerAuthSDK.biometricStatus
```

The next chapters explain in more detail the usage of the returned `PowerAuthBiometricStatus` object.

### System Availability

To check whether the biometrics is available at the system level, use the following code:

```swift
// Get biometric status
let biometricStatus = powerAuthSDK.biometricStatus
switch biometricStatus.systemStatus {
    case .notSupported: print("Biometry is not supported.")
    case .notAvailable: print("Biometry is not available at this moment.")
    case .notEnrolled: print("Biometry is supported, but not enrolled.")
    case .lockout: print("Biometry is supported, but it has been locked out.")
    case .available: print("Biometry is available right now.")
}
// If you want to adjust localized strings or icons presented to the user,
// you can use the following code to determine the type of biometry available
// on the system:
switch biometricStatus.biometryType {
    case .touchID: print("You can use Touch ID")
    case .faceID: print("You can use Face ID")
    case .none: print("Biometry is not supported or not enrolled")
}
```

### Activation Availability

To check whether activation is configured for authentication with biometrics, use the following code:

```swift
// Get biometric status
let biometricStatus = powerAuthSDK.biometricStatus
// Determine overall availability
if biometricStatus.isAuthenticationWithBiometricsAvailable {
    // Equal to call:
    //   powerAuthSDK.isAuthenticationWithBiometricsAvailable
}
// Determine whether local activation has biometric factor configured.
if biometricStatus.isBiometricFactorConfigured {
    // Equal to call
    //   powerAuthSDK.hasBiometryFactor()
}
```

### Application Availability

The last check is fully under your control. By keeping the biometry settings flag, for example, a `bool` in `UserDefaults`, you are able to show expected user Touch or Face ID status (in a disabled state, though) even in the case biometry is not enabled or when no finger or face is enrolled on the device.


## Enable Biometry

In case an activation does not yet have biometry-related factor data, and you would like to enable Touch or Face ID support, use the following code:

```swift
// Establish biometric data using the provided password
powerAuthSDK.addBiometryFactor(password: "1234") { error in
    if let error  {
        // Error occurred, report it to the user

        // It's also recommended to fetch activation's status to synchronize biometric factor
        // configuration with the server.
    } else {
        // Everything went OK, biometry is ready to be used
    }
}
```

## Disable Biometry

To remove biometry-related factor data used by Touch or Face ID use the following code:

```swift
// Remove biometric data
powerAuthSDK.removeBiometryFactor { error in
    if let error {
        // handle error

        // It's recommended to fetch activation's status to synchronize biometric factor
        // configuration with the server.
    }
}
```

## Fetch Biometry Credentials In Advance

You can acquire biometry credentials in advance in case business processes require computing two or more different PowerAuth biometry authentication codes in one interaction with the user. To achieve this, the application must acquire the custom-created `PowerAuthAuthentication` object first and then use it for the required authentication code calculations. It's recommended to keep this instance referenced only for a limited time, required for all future authentication code calculations.

Be aware, that you must not execute the next HTTP request signed with the same credentials when the previous one fails with the 401 HTTP status code. If you do, then you risk blocking the user's activation on the server.

To obtain biometry credentials for the future authentication code calculation, call the following code:

```swift
// Authenticate user with biometry and obtain PowerAuthAuthentication credentials for future authentication code calculation.
powerAuthSDK.authenticateUsingBiometry(withPrompt: "Authenticate to sign in") { authentication, error in
    if let authentication {
        // Success, you can use the provided PowerAuthAuthentication object for the authentication code calculation.
        // The provided authentication object is preconfigured for possession+biometry factors
    }
}
```

## Biometry Factor-Related Key Lifetime

By default, the biometry factor-related key is **NOT** invalidated after the biometry enrolled in the system is changed. For example, if the user adds or removes the finger or enrolls with a new face, then the biometry factor-related key is still available for the signing operation. To change this behavior, you have to provide the `PowerAuthBiometricConfiguration` object with the `invalidateBiometricFactorAfterChange` parameter set to `true` and use that configuration for the `PowerAuthSDK` instance construction:

```swift
// Prepare your PA config
let configuration = PowerAuthConfiguration()
// ...

// Prepare PowerAuthBiometricConfiguration
// Set true to the 'invalidateBiometricFactorAfterChange' property.
let biometricConfiguration = PowerAuthBiometricConfiguration()
biometricConfiguration.invalidateBiometricFactorAfterChange = true

// Init PowerAuthSDK instance
let powerAuthSDK = try PowerAuthSDK(configuration: configuration, biometricConfiguration: biometricConfiguration, clientConfiguration: nil)
```

<!-- begin box warning -->
Be aware that the configuration above is effective only for the new keys. So, if your application is already using the biometry factor-related key with a different configuration, then the configuration change doesn't change the existing key. You have to [disable](#disable-biometry) and [enable](#enable-biometry) biometry to apply the change.
<!-- end -->

## Fallback biometry to device passcode

By default, the fallback from biometric authentication to authenticate with the device's passcode is not allowed. To change this behavior, you have to provide the `PowerAuthBiometricConfiguration` object with the `allowFallbackToDevicePasscode` parameter set to `true` and use that configuration for the `PowerAuthSDK` instance construction:

```swift
// Prepare your PA config
let configuration = PowerAuthConfiguration()
// ...

// Prepare PowerAuthBiometricConfiguration
// Set true to the 'allowFallbackToDevicePasscode' property.
let biometricConfiguration = PowerAuthBiometricConfiguration()
biometricConfiguration.allowFallbackToDevicePasscode = true

// Init PowerAuthSDK instance
let powerAuthSDK = try PowerAuthSDK(configuration: configuration, biometricConfiguration: biometricConfiguration, clientConfiguration: nil)
``` 

Once the configuration above is used, then the `invalidateBiometricFactorAfterChange` option does not affect the biometry factor-related key lifetime. 

<!-- begin box warning -->
It's not recommended to allow fallback to device passcodes if your application falls under EU banking regulations or your application needs to distinguish between the biometric and the knowledge-factor-based authentication codes. This is because if the biometry factor-related key is unlocked with the device's passcode, then it's no longer a biometric factor.
<!-- end -->

## LAContext support

In case you require advanced customization to the system biometric dialog, then you can use your own `LAContext` instance set to `PowerAuthAuthentication` or in some functions. For example:

```swift
// Prepare LAContext
let laContext = LAContext()
laContext.localizedReason = "Authenticate to remove activation"

// Prepare PowerAuthAuthentication with context
let authentication = PowerAuthAuthentication.possessionWithBiometry(context: laContext)
// Now you can use authentication in some functions...
powerAuthSDK.removeActivation(with: authentication) { error in
    // ...
}

// Fetch the biometry key in advance using LAContext
powerAuthSDK.authenticateUsingBiometry(withContext: laContext) { authentication, error in
    if let authentication = authentication {
        // success
    }
}
```

The usage of `LAContext` has the following limitations:

- It's effective from iOS 11 because on the older operating systems, the context doesn't support essential properties, such as `localizedReason`.
- Don't alter the `interactionNotAllowed` property. If you do, then the internal SDK implementation rejects the context, and an error is reported.

Be aware that PowerAuth automatically invalidates the application provided `LAContext` after use. This is because once the context is successfully evaluated then it can be used for a quite long time to fetch the data protected with the biometry with no prompt displayed. The exact time of validity is undocumented, but our experiments show that iOS prompts for biometric authentication again after more than 5 minutes.

If you plan to pre-authorize `LAContext` and use it for multiple biometry authentication code calculations in a row, then please consider the following things first:

- Make sure that you make context invalid once it's no longer needed.
- Multiple authentication codes in a row could be problematic if your application falls under EU banking regulations.
- It would be difficult to prove that the user authorized the request if your application contains a bug and does the authentication on the user's behalf or with the wrong context.

If you still insist to re-use `LAContext` then you have to alter `PowerAuthBiometricConfiguration` and set `invalidateLocalAuthenticationContextAfterUse` to `false`.

## Read Next

- [Biometry Troubleshooting](Biometry-Troubleshooting.md)
