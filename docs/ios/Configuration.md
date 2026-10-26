# SDK Configuration

<!-- SIDEBAR _Sidebar.md -->
<!-- BREADCRUMB iOS href=../PowerAuth-SDK-for-iOS -->

To use PowerAuth SDK, simply add the following imports into your code:

```swift
import PowerAuth2
```

From now on, you can use `PowerAuthSDK` and other classes in your project. To configure your `PowerAuthSDK` instance, you need the following values from the PowerAuth Server:

- `MOBILE_SDK_CONFIG` - String that contains cryptographic configuration.

You also need to specify your instance ID (by default, this can be an app bundle ID). This is because one application may use more than one custom instance of `PowerAuthSDK`, and the identifier is the way to distinguish these instances while working with Keychain data.

Finally, you need to know the location of your [PowerAuth Standard RESTful API](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Standard-RESTful-API.md) endpoints. That path should contain everything that goes before the `/pa/**` prefix of the API endpoints.

To sum it up, in order to configure the `PowerAuthSDK` instance, add the following code to your application delegate:

```swift
func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplicationLaunchOptionsKey: Any]?) -> Bool {

    // Prepare the configuration
    let configuration = PowerAuthConfiguration(
        instanceId: Bundle.main.bundleIdentifier!,
        baseEndpointUrl: "https://<your-domain>/enrollment-server",
        configuration: "ARDDj6EB6iAUtNm...KKEcBxbnH9bMk8Ju3K1wmjbA==")
    do {
        // Create a PowerAuthSDK instance with the configuration
        let powerAuth = try PowerAuthSDK(configuration: configuration)
    } catch let err as NSError {
        switch err.powerAuthErrorCode {
        case .wrongParameter:
            // Invalid configuration.
        case .invalidActivationData:
            // Unrecognized data format. You can log this event, clear data and retry SDK construction
            try PowerAuthSDK.cleanupInstanceData(configuration: configuration)
        case .upgradeSDK:
            // Upgrade SDK in your application
        default:
            // other errors
            break
        }
    }
}
```

## Additional configuration

The `PowerAuthConfiguration` has the following additional properties:

- `algorithm` - Alters [algorithm](#algorithms-for-communication) used for the communication with the PowerAuth Server.
- `offlineAuthenticationCodeComponentLength` - Alters the default component length for the [offline authentication code](Authentication-Codes.md#symmetric-offline-multi-factor-authentication-code). The values between 4 and 8 are allowed. The default value is 8.
- `keychainKey_Biometry` - Specifies the 'key' used to store the `PowerAuthSDK` instance’s biometry-related key in the biometry keychain. If not set, the `instanceId` is applied. Do not alter this configuration unless you have a valid reason to do so.

## Biometric configuration

The `PowerAuthBiometricConfiguration` object configures biometric authentication in the `PowerAuthSDK` object. It has the following configuration properties:

- `invalidateBiometricFactorAfterChange` - If set to `true`, the biometric factor is invalidated when fingers are added or removed for Touch ID, or when the user re-enrolls for Face ID. The default value is false (i.e., changing biometric settings in the system does not invalidate the biometric factor).
- `allowFallbackToDevicePasscode` -  If set to `true`, an item protected with biometry can also be accessed using the device passcode. If enabled, the `invalidateBiometricFactorAfterChange` option has no effect. The default value is `false`, meaning fallback to the device passcode is not enabled.
- `invalidateLocalAuthenticationContextAfterUse` - If set to `true`, the `LAContext` object provided by the application is invalidated after use in the SDK. The default value is true, meaning `LAContext` cannot be reused for retrieving keys protected with biometry.

## HTTP client configuration

The `PowerAuthClientConfiguration` object contains configuration for a HTTP client used internally by `PowerAuthSDK` object. It has the following configuration properties:

- `defaultRequestTimeout` - Property that specifies the default HTTP client request timeout. The default value is 20.0 seconds.
- `sslValidationStrategy` - Property that specifies the SSL validation strategy applied by the client. The default value is the default `URLSession` behavior. See [Working with Invalid SSL Certificates](Common-SDK-Tasks.md#working-with-invalid-ssl-certificates) chapter for more details.
- `requestInterceptors`- Property that specifies the list of [request interceptors](Additional-Features.md#request-interceptors) used by the client before the request is executed. The default value is `nil`.
- `userAgent` -  Property that specifies the content of User-Agent request header. The default is value calculated in `PowerAuthSystem.defaultUserAgent()` function. If you set `nil` to this property, then the default value provided by operating system is used.

## Keychain configuration

The `PowerAuthKeychainConfiguration` object contains configuration for a keychain-based storage used by `PowerAuthSDK` class internally.

<!-- begin box warning -->
We strongly discourage you from altering the properties in this configuration unless you know what you are doing.
<!-- end -->

The configuration contains the following properties:

- `keychainInstanceName_Status` - Property that specifies the name of the Keychain service used to store statuses for different PowerAuth instances. You should not change this property unless you have a valid reason to do so.
- `keychainInstanceName_Possession` - Property that specifies the name of the Keychain service used to store possession factor related key (one value for all `PowerAuthSDK` instances).
- `keychainInstanceName_Biometry` - Property that specifies the name of the Keychain service used to store biometry related keys for different `PowerAuthSDK` instances.
- `keychainInstanceName_TokenStore` - Property that specifies the name of the Keychain service used to store content of `PowerAuthToken` objects.
- `keychainKey_Possession` - Property that specifies a storage key used to store possession factor related key in an associated possession Keychain service.

The following properties are defined, but deprecated:

- `keychainAttribute_AccessGroup` - Property that specifies a keychain access group in case that keychain is shared between multiple applications or between application and its extensions. Use configuration for [Activation Data Sharing](Share-Activation-Data.md#configure-activation-data-sharing) instead.
- `keychainAttribute_UserDefaultsSuiteName` - Property that specifies the name of `UserDefaults` suite to store the flag indicating that application has been re-installed. If the value is not provided, then `UserDefaults.standardUserDefaults` suite is used. Use configuration for [Activation Data Sharing](Share-Activation-Data.md#configure-activation-data-sharing) instead.
- `linkBiometricItemsToCurrentSet` - If set, then the item protected with the biometry is invalidated if fingers are added or removed for Touch ID, or if the user re-enrolls for Face ID. The default value is `false` (e.g. changing biometry in the system doesn't invalidate the entry). Use `PowerAuthBiometricConfiguration.invalidateBiometricFactorAfterChange` instead.
- `allowBiometricAuthenticationFallbackToDevicePasscode` - If set to `true`, then the item protected with the biometry can be accessed also with a device passcode. If set, then `linkBiometricItemsToCurrentSet` option has no effect. The default is `false`, so fallback to device's passcode is not enabled. Use `PowerAuthBiometricConfiguration.allowFallbackToDevicePasscode` instead.
- `invalidateLocalAuthenticationContextAfterUse` - If set to `true`, then the `LAContext` object provided by application is invalidated after the use in SDK. The default value is `true`, so `LAContext` cannot be reused for getting keys protected with biometry. Use `PowerAuthBiometricConfiguration.invalidateLocalAuthenticationContextAfterUse` instead.


## Algorithms for Communication

The PowerAuth Mobile SDK supports multiple algorithms for communication with the **PowerAuth Server**. Each algorithm has unique properties, allowing you to choose whether to prioritize security, performance, or a balance of both.

The following algorithms are currently supported:

- `EC_P384_ML_L3` — **default algorithm**  
  - Provides the best balance between performance and security, including post-quantum resistance.  
  - Uses a **hybrid** scheme combining P-384–based ECC with ML-KEM-768 and ML-DSA-65 algorithms.  
  - Requires PowerAuth Server **2.0 or later**.

- `EC_P384_ML_L5`
  - Provides the highest level of security, including post-quantum resistance.  
  - Uses a **hybrid** scheme combining P-384–based ECC with ML-KEM-1024 and ML-DSA-87 algorithms.  
  - Requires PowerAuth Server **2.0 or later**.

- `EC_P384`
  - Offers excellent performance and stronger security than the legacy protocol V3.3, but is not quantum-resistant.  
  - This algorithm is based on P-384 ECC and should be used only if your infrastructure cannot yet handle the higher load introduced by post-quantum algorithms.  
  - Requires PowerAuth Server **2.0 or later**.

- `LEGACY_P256`
  - Based on P-256 ECC and fully compatible with PowerAuth protocol V3.3.  
  - Intended to help you migrate your application code to the API changes introduced in PowerAuth Mobile SDK 2.0 while maintaining compatibility with your existing infrastructure. Once your PowerAuth Server is upgraded to version 2.0 or later, you should switch to at least `EC_P384`.  
  - Requires PowerAuth Server **1.9 or later**.

<!-- begin box info -->
If you select `LEGACY_P256` algorithm, then SDK may behave slightly different in some rare cases. The rest of the documentation will use **"legacy mode"** or **"legacy activation"** terminology to highlight such situation.
<!-- end -->

The default algorithm can be overridden by specifying a different one in the SDK configuration:

```swift
// Prepare the configuration
let configuration = PowerAuthConfiguration(
    instanceId: Bundle.main.bundleIdentifier!,
    baseEndpointUrl: "https://<your-domain>/enrollment-server",
    configuration: "ARDDj6EB6iAUtNm...KKEcBxbnH9bMk8Ju3K1wmjbA==",
    algorithm: .EC_P384_ML_L5)

// Create a PowerAuthSDK instance with the configuration
let powerAuth = try PowerAuthSDK(configuration: configuration)
```

The selected algorithm cannot be changed after a `PowerAuthSDK` instance is created, but it can be updated across the lifetime of your application. If the selected algorithm does not match the one used for the activation currently present on the device, the [authenticated protocol upgrade](Authenticated-Protocol-Upgrade.md) process must be performed to switch to the new algorithm.

## Read Next

- [Device Activation](Device-Activation.md)
