# SDK Configuration

In order to be able to configure your `PowerAuthSDK` instance, you need the following values from the PowerAuth Server:

- `MOBILE_SDK_CONFIG` - String that contains cryptographic configuration.

You also need to specify your instance ID (by default, this can be for example an app package name). This is because one application may use more than one custom instance of `PowerAuthSDK`, and the identifier is the way to distinguish these instances while working with Keychain data.

Finally, you need to know the location of your [PowerAuth Standard RESTful API](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Standard-RESTful-API.md) endpoints. That path should contain everything that goes before the `/pa/**` prefix of the API endpoints.

To sum it up, in order to configure the `PowerAuthSDK` default instance, add the following code to your application main activity `onCreate()` method:

```kotlin
val INSTANCE_ID = applicationContext.packageName
val MOBILE_SDK_CONFIG = "MTIzNDU2Nz...jc4OTAxMg=="
val API_SERVER = "https://<your-domain>/enrollment-server"

try {
    val configuration = PowerAuthConfiguration.Builder(
        INSTANCE_ID,
        API_SERVER,
        MOBILE_SDK_CONFIG)
        .build()
    val powerAuthSDK = PowerAuthSDK.Builder(configuration)
        .build(applicationContext)
} catch (exception: PowerAuthErrorException) {
    when (exception.powerAuthErrorCode) {
        PowerAuthErrorCodes.INVALID_ACTIVATION_DATA -> {
            // Activation data format is not recognized
            // Clear activation data and retry PowerAuthSDK object construction
            PowerAuthSDK.cleanupInstanceData(applicationContext, configuration)
        }
        PowerAuthErrorCodes.INSUFFICIENT_KEYCHAIN_PROTECTION -> {
            // This device doesn't support the requested level of keychain protection.
            // See next chapters for details
        }
        PowerAuthErrorCodes.UPGRADE_SDK -> {
            // You have somehow downgraded your application and activation data
            // is in newer format. You can clear activation data and retry the operation.
        }
        else -> Log.d(TAG, "Other error")
    }    
}
```

If you don't provide the application's context to the `build()` method, then PowerAuthSDK will fail to register its components for the application's lifecycle callbacks. To fix this, please use the following code in your application's `onCreate()` method:

```kotlin
PowerAuthAppLifecycleListener.getInstance().registerForActivityLifecycleCallbacks(this) // "this" is Application
```


## Additional configuration

The `PowerAuthConfiguration.Builder` class provides the following additional methods that can alter the configuration:

- `algorithm()` - Alters [algorithm](#algorithms-for-communication) used for the communication with the PowerAuth Server.
- `offlineAuthenticationCodeComponentLength()` - Alters the default component length for the [offline authentication code](Android-Authentication-Codes.md#symmetric-offline-multi-factor-authentication-code). The values between 4 and 8 are allowed. The default value is 8.

## Biometric configuration

The `PowerAuthBiometricConfiguration.Builder` class contains biometric configuration for `PowerAuthSDK` class. It has the following configuration properties:

- `invalidateBiometricFactorAfterChange()` - Function specifies whether the biometric factor key is invalidated if fingers are added or removed, or if the user re-enrolls for face. See [Biometry Factor-Related Key Lifetime](Android-Biometric-Authentication-Setup.md#biometry-factor-related-key-lifetime) chapter for more details.
- `confirmBiometricAuthentication()` - Function specifies whether the user's confirmation will be required after the successful biometric authentication. See [Biometric Authentication Confirmation](Android-Biometric-Authentication-Setup.md#biometric-authentication-confirmation) chapter for more details.
- `authenticateOnBiometricKeySetup()` - Function specifies whether setup for biometric factor always require a biometric authentication. See [Enable Biometric Authentication](Android-Biometric-Authentication-Setup.md#enable-biometric-authentication) chapter for more details.
- `enableFallbackToSharedBiometryKey()` - Function specifies whether `PowerAuthSDK` instance should also do additional lookup for a legacy biometric key, previously shared between multiple `PowerAuthSDK` object instances. The default value is `true` and the fallback is enabled. If your application is using multiple `PowerAuthSDK` instances, then it's recommended to set this option to `false` to avoid use of the shared key between such instances.
- `useLegacySymmetricKey()` – Specifies whether the `PowerAuthSDK` instance should use the legacy symmetric key for protecting biometric key data. When set to `true`, the legacy AES-KDF from PowerAuth Mobile SDK 1.x is used instead of the newer HMAC-KDF based protection. Keys previously configured under SDK 1.x are unaffected regardless of this setting — this option controls only which KDF is applied when a **new** biometric factor is configured. It is recommended to keep this option set to `false` so that newly enrolled biometric factors use the new HMAC-KDF protection.


## HTTP client configuration

The `PowerAuthClientConfiguration.Builder` class contains configuration for a HTTP client used internally by `PowerAuthSDK` class. It has the following configuration properties:

- `timeouts()` - Function specifies connection and read timeout in milliseconds.
- `allowUnsecuredConnection()` - Enables or disables connection to unsecured servers. Do not use this option in the production build of your application. 
- `clientValidationStrategy()` - Specifies TLS client validation strategy. See [Working with Invalid SSL Certificates](Android-Common-SDK-Tasks.md#working-with-invalid-ssl-certificates) for more details.
- `requestInterceptor()` - Adds a [request interceptor](Android-Additional-Features.md#request-interceptors) used by the client before the request is executed.
- `userAgent()` - Specifies value for User-Agent HTTP request header. See [Custom User-Agent](Android-Additional-Features.md#custom-user-agent) chapter for more details.

## Keychain configuration

The `PowerAuthKeychainConfiguration.Builder` class contains configuration for a keychain-based storage used by `PowerAuthSDK` class internally. The configuration contains the following properties:

- `minimalRequiredKeychainProtection()` - Function specifies minimal required keychain protection level that must be supported on the current device. See [Activation Data Protection](#activation-data-protection) chapter for more details.

The following properties are also available for configuration but are not recommended to be altered under typical circumstances, as changing them may impact the library’s stability or intended behavior:

- `keychainStatusId()` - Function specifies name of the Keychain file used for storing the status information.
- `keychainBiometryId()` - Function specifies name of the Keychain file used for storing the biometry key information.
- `keychainTokenStoreId()` - Function specifies name of the Keychain file used for storing the access tokens.
- `keychainKeyBiometry()` - Function specifies name of the key to the biometry Keychain to store biometry-factor protection key.

The following properties are deprecated and moved to [Biometric Configuration](#biometric-configuration) class:

- `linkBiometricItemsToCurrentSet()` -  Function specifies whether the item protected with the biometry is invalidated if fingers are added or removed, or if the user re-enrolls for face. See [Biometry Factor-Related Key Lifetime](Android-Biometric-Authentication-Setup.md#biometry-factor-related-key-lifetime) chapter for more details.
- `confirmBiometricAuthentication()` - Function specifies whether the user's confirmation will be required after the successful biometric authentication. See [Biometric Authentication Confirmation](Android-Biometric-Authentication-Setup.md#biometric-authentication-confirmation) chapter for more details.
- `authenticateOnBiometricKeySetup()` - Function specifies whether biometric key setup always require a biometric authentication. See [Enable Biometric Authentication](Android-Biometric-Authentication-Setup.md#enable-biometric-authentication) chapter for more details.
- `enableFallbackToSharedBiometryKey()` - Function specifies whether `PowerAuthSDK` instance should also do additional lookup for a legacy biometric key, previously shared between multiple PowerAuthSDK object instances. The default value is `true` and the fallback is enabled. If your application is using multiple `PowerAuthSDK` instances, then it's recommended to set this option to `false` to avoid use of the shared key between such instances.

## Activation Data Protection

By default, the PowerAuth Mobile SDK for Android encrypts the local activation data with a symmetric key generated by the Android KeyStore on Android 6 and newer devices. On older devices, or if the device has an unreliable KeyStore implementation, then the fallback to unencrypted storage, based on private [SharedPreferences](https://developer.android.com/reference/android/content/SharedPreferences) is used. If your application requires a higher level of activation data protection, then you can enforce the level of protection in `PowerAuthKeychainConfiguration`:

```kotlin
try {
    val keychainConfig = PowerAuthKeychainConfiguration.Builder()
        .minimalRequiredKeychainProtection(KeychainProtection.HARDWARE)
        .build()
    // Apply keychain configuration
    val powerAuthSDK = PowerAuthSDK.Builder(configuration)
        .keychainConfiguration(keychainConfig)
        .build(context)
} catch (e: PowerAuthErrorException) {
    // Failed to construct `PowerAuthSDK` due to insufficient keychain protection.
}
```

You can also determine the level of keychain protection before `PowerAuthSDK` object creation by calling:

```kotlin
val keychainProtectionLevel = KeychainFactory.getKeychainProtectionSupportedOnDevice(context)
```

The following levels of keychain protection are defined:

- `NONE` - The content of the keychain is not encrypted and therefore not protected. This level of protection is typically reported on devices older than Android Marshmallow, or in case the device has faulty KeyStore implementation.

- `SOFTWARE` - The content of the keychain is encrypted with a key generated by Android KeyStore, but the key is protected only on the operating system level. The security of the key material relies solely on software measures, which means that a compromise of the Android OS (such as a "root" exploit) might up revealing this key.

- `HARDWARE` - The content of the keychain is encrypted with a key generated by Android KeyStore and the key is stored and managed by [Trusted Execution Environment](https://en.wikipedia.org/wiki/Trusted_execution_environment).

- `STRONGBOX` - The content of the keychain is encrypted with a key generated by Android KeyStore and the key is stored inside of Secure Element (e.g. StrongBox). This is the highest level of Keychain protection currently available, but not enabled by default. See [note below](#strongbox-support-note).

Be aware, that enforcing the required level of protection must be properly reflected in your application's user interface. That means that you should inform the user in case the device has insufficient capabilities to run your application securely.

### StrongBox Support Note

The StrongBox-backed keys are by default turned off due to poor reliability and low performance of StrongBox implementations on the current Android devices. If you want to turn support on in your application, then use the following code at your application's startup:

```kotlin
try {
    KeychainFactory.setStrongBoxEnabled(context, true)
} catch (e: PowerAuthErrorException) {
    // You must alter the configuration before any keychain is accessed.
    // Basically, you should not create any PowerAuthSDK instance before the change.
}
```

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

```kotlin
try {
    val configuration = PowerAuthConfiguration.Builder(
        INSTANCE_ID,
        API_SERVER,
        MOBILE_SDK_CONFIG)
        .algorithm(PowerAuthAlgorithm.EC_P384_ML_L5)
        .build()
    val powerAuthSDK = PowerAuthSDK.Builder(configuration)
        .build(applicationContext)
} catch (exception: PowerAuthErrorException) {
    // Failed to construct `PowerAuthSDK` due to insufficient keychain protection.
    // (See next chapter for details)
}
```

The selected algorithm cannot be changed after a `PowerAuthSDK` instance is created, but it can be updated across the lifetime of your application. If the selected algorithm does not match the one used for the activation currently present on the device, the [authenticated protocol upgrade](Android-Authenticated-Protocol-Upgrade.md) process must be performed to switch to the new algorithm.

## Read Next

- [Device Activation](Android-Device-Activation.md)
