# Migration from 1.7.x to 1.8.x

PowerAuth Mobile SDK in version `1.8.0` provides the following improvements:

- Added support for simplified configuration. The SDK is now configured with using one Base64 encoded string instead of three separate values.
- Added support for PowerAuth protocol version 3.2, including End-To-End encryption improvements and time synchronized with the server.
- We have replaced the term 'commit activation' with 'persist activation' in our terminology. This change clearly distinguishes between the commit activation process on the server and the activation completion process on the mobile device.

### Compatibility with PowerAuth Server

- This release is fully compatible with PowerAuth Server version `1.5.0` and newer.

### Legacy SDK configuration

In case you need to still use the legacy setup to configure older version of PowerAuth mobile SDK, then you can use `get-legacy-config.swift` script available at `scripts` folder. For example:

```
./scripts/get-legacy-config.swift ARDTWDPw20CBb+aUeIuWy25MEHy89d2ySbQR2QoCb3taB1EBAUEEPspwnZzj7AOw0emEk/J51V16ZpkDMGE3VT3vzb+3Wh9qEA8MAJBTLPJ3XgFkr6OBVQCkpBezpbXOx1xHvVAqyQ==
Legacy PowerAuth configuration:
   appKey                : 01gz8NtAgW/mlHiLlstuTA==
   appSecret             : fLz13bJJtBHZCgJve1oHUQ==
   masterServerPublicKey : BD7KcJ2c4+wDsNHphJPyedVdemaZAzBhN1U9782/t1ofahAPDACQUyzyd14BZK+jgVUApKQXs6W1zsdcR71QKsk=
```

## Android

### API changes

- `PowerAuthConfiguration`
  - `Builder` constructor now supports only the simplified configuration. For example:
    ```java
    final PowerAuthConfiguration configuration = new PowerAuthConfiguration.Builder(
                "your-instance-id",
                "https://api.wultra.com/enrollment-server",
                "ARDDj6EB6iA...H9bMk8Ju3K1wmjbA=="
            ).build();
    ```

- `PowerAuthSDK.Builder.build()` now require to use application's context to build instance of `PowerAuthSDK`. If you don't have such context available, then please use the following code in your application's `onCreate()` method:
  ```kotlin
  PowerAuthAppLifecycleListener.getInstance().registerForActivityLifecycleCallbacks(this) // "this" is Application
  ```

- The following methods are now deprecated in `PowerAuthAuthentication` class:
  - All variants of `commitWithPassword()` are now replaced with `persistWithPassword()`
  - All variants of `commitWithPasswordAndBiometry()` are now `persistWithPasswordAndBiometry()`

- The following methods are now deprecated in `PowerAuthSDK` class:
  - `commitActivationWithAuthentication()` is now `persistActivationWithAuthentication()`
  - All variants of `commitActivationWithPassword()` are now `persistActivationWithPassword()`
  - All variants of `commitActivation()` are now `persistActivation()`

- The `ICommitActivationWithBiometryListener` is now deprecated and you can use `IPersistActivationWithBiometryListener` as a replacement.

- The `PowerAuthAuthentication` object is now immutable object.

- The biometry-related methods in `PowerAuthSDK` are no longer annotated as `@RequiresApi(api = Build.VERSION_CODES.M)`. This change may lead to a several dead code branches in your code if you still support devices older than Android 6.0.

- Removed all interfaces deprecated in release `1.7.x`

### Other changes

#### Synchronized time

The requirement for the time synchronized with the server has the following impact to your code:

- If you use custom **End-To-End Encryption** in your application, then it's recommended to make sure the time is synchronized with the server:
  ```kotlin
  val timeService = powerAuthSDK.timeSynchronizationService
  if (!timeService.isTimeSynchronized) {
    timeService.synchronizeTime(object : ITimeSynchronizationListener {
      override fun onTimeSynchronizationSucceeded() {
        // Success
      }

      override fun onTimeSynchronizationFailed(t: Throwable) {
        // Failure
      }
    })
  }
  ```

- If you use **Token-Based Authentication**, then you should use the new API provided by `PowerAuthTokenStore` that guarantee that time is synchronized before the token header is calculated:
  ```kotlin
  val task = powerAuthSDK.tokenStore.generateAuthorizationHeader(context, "MyToken", object : IGenerateTokenHeaderListener {
    override fun onGenerateTokenHeaderSucceeded(header: PowerAuthAuthorizationHttpHeader) {
        val httpHeaderKey = header.key
        val httpHeaderValue = header.value
    }

    override fun onGenerateTokenHeaderFailed(t: Throwable) {
        // Failure
    }
  })
  ```

Visit [Synchronized Time](https://developers.wultra.com/components/powerauth-mobile-sdk/develop/documentation/PowerAuth-SDK-for-Android#synchronized-time) chapter in our documentation for more details.

#### End-To-End Encryption

- Encrypted request now contains new property `timestamp` with type `long`, please update your model objects. For example:
  ```json
  {
    "ephemeralPublicKey" : "BASE64-DATA-BLOB",
    "encryptedData": "BASE64-DATA-BLOB",
    "mac" : "BASE64-DATA-BLOB",
    "nonce" : "BASE64-NONCE",
    "timestamp" : 1694172789256
  }
  ```
- Encrypted response now contains two new properties: `timestamp` with `long` and `nonce` with `String`. Please update your model objects:
  ```json
  {
    "encryptedData": "BASE64-DATA-BLOB",
    "mac" : "BASE64-DATA-BLOB",
    "nonce" : "BASE64-NONCE",
    "timestamp": 1694172789256
  }
  ```

## iOS & tvOS

### API changes

- `PowerAuthConfiguration` - class now supports only the simplified configuration.
  - Use new object constructor with all required parameters:
    ```swift
    let config = PowerAuthConfiguration(
        instanceId: "your-instance-id",
        baseEndpointUrl: "https://api.wultra.com/enrollment-server",
        configuration: "ARDDj6EB6iA...H9bMk8Ju3K1wmjbA=="
    )
    ```
  - Removed `applicationKey`, `applicationSecret`, `masterServerPublicKey` properties.
  - Constructor with no parameters is no longer supported.

- The following methods in `PowerAuthSDK` are now deprecated:
  - `commitActivation(with:)` is now replaced with `persistActivation(with:)`
  - `commitActivation(withPassword:)` is now replaced with `persistActivation(withPassword:)`

- The following methods in `PowerAuthAuthentication` are now deprecated:
  - `.commitWithPassword(password:)` is replaced with `.persistWithPassword(password:)`
  - `.commitWithPassword(password:customPossessionKey:)` is now `.persistWithPassword(password:customPossessionKey:)`
  - `.commitWithPasswordAndBiometry(password:)` is now `.persistithPasswordAndBiometry(password:)`
  - `.commitWithPasswordAndBiometry(password:customBiometryKey:customPossessionKey:)` is now `.persistWithPasswordAndBiometry(password:customBiometryKey:customPossessionKey:)`

- The `PowerAuthAuthentication` object is now immutable and no longer implements `NSCopying` protocol.

- `PowerAuthErrorCode` now contains new `.timeSynchronization` case indicating a problem with the time synchronization.

- Removed all interfaces deprecated in release `1.7.x`

### Other changes

#### Synchronized time

The requirement for the time synchronized with the server has the following impact to your code:

- If you use custom **End-To-End Encryption** in your application, then it's recommended to make sure the time is synchronized with the server:
  ```swift
  if !powerAuthSdk.timeSynchronizationService.isTimeSynchronized {
    let task = powerAuthSdk.timeSynchronizationService.synchronizeTime(callback: { error in
      if error == nil {
          // Success, time has been properly synchronized
      } else {
          // Failed to synchronize the time
      }
    }, callbackQueue: .main)
  }
  ```
- If you use **Token-Based Authentication**, then you should use the new API provided by `PowerAuthTokenStore` that guarantee that time is synchronized before the token header is calculated:
  ```swift
  powerAuthSdk.tokenStore.generateAuthorizationHeader(withName: "MyToken") { header, error in
    if let header = header {
        let httpHeader = [ header.key : header.value ]
    } else {
        // failure
    }
  }
  ``` 

Visit [Synchronized Time](https://developers.wultra.com/components/powerauth-mobile-sdk/develop/documentation/PowerAuth-SDK-for-iOS#synchronized-time) chapter in our documentation for more details.

#### End-To-End Encryption

- Encrypted request now contains new property `timestamp` with type `UInt64`, please update your model objects. For example:
  ```json
  {
    "ephemeralPublicKey" : "BASE64-DATA-BLOB",
    "encryptedData": "BASE64-DATA-BLOB",
    "mac" : "BASE64-DATA-BLOB",
    "nonce" : "BASE64-NONCE",
    "timestamp" : 1694172789256
  }
  ```
- Encrypted response now contains two new properties: `timestamp` with `UInt64` and `nonce` with `String`. Please update your model objects:
  ```json
  {
    "encryptedData": "BASE64-DATA-BLOB",
    "mac" : "BASE64-DATA-BLOB",
    "nonce" : "BASE64-NONCE",
    "timestamp": 1694172789256
  }
  ```

## iOS & tvOS App Extensions

### API changes

- The `PowerAuthAuthentication` object is now immutable object and no longer implement `NSCopying` protocol.

## watchOS

### API changes

- The `PowerAuthAuthentication` object is now immutable object and no longer implement `NSCopying` protocol.