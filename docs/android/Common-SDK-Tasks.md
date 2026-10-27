# Common SDK Tasks

<!-- SIDEBAR _Sidebar.md -->
<!-- BREADCRUMB Android href=../PowerAuth-SDK-for-Android -->

## Error Handling

The PowerAuth SDK uses the following types of exceptions:

- `FailedApiException` - is typically returned to callbacks when an asynchronous HTTP request ends on error.
- `ErrorResponseApiException` - is typically returned to callbacks when an asynchronous HTTP request ends on an error and the error model object is present in the response.
- `PowerAuthErrorException` - typically covers all other erroneous situations. You can investigate a detailed reason for failure by getting the integer, from the set of `PowerAuthErrorCodes` constants.

Here's an example of a typical error-handling procedure:

```kotlin
val t: Throwable // reported in asynchronous callback
when (t) {
    is PowerAuthErrorException -> {
        when (t.powerAuthErrorCode) {
            PowerAuthErrorCodes.NETWORK_ERROR -> Log.d(TAG, "Error code for error with network connectivity or download")
            PowerAuthErrorCodes.SIGNATURE_ERROR -> Log.d(TAG, "Error code for error in signature calculation")
            PowerAuthErrorCodes.INVALID_ACTIVATION_STATE -> Log.d(TAG, "Error code for error that occurs when activation state is invalid")
            PowerAuthErrorCodes.INVALID_ACTIVATION_DATA -> Log.d(TAG, "Error code for error that occurs when activation data is invalid")
            PowerAuthErrorCodes.MISSING_ACTIVATION -> Log.d(TAG, "Error code for error that occurs when activation is required but missing")
            PowerAuthErrorCodes.PENDING_ACTIVATION -> Log.d(TAG, "Error code for error that occurs when pending activation is present and work with completed activation is required")
            PowerAuthErrorCodes.INVALID_ACTIVATION_CODE -> Log.d(TAG, "Error code for error that occurs when invalid activation code is provided.")
            PowerAuthErrorCodes.BIOMETRY_CANCEL -> Log.d(TAG, "Error code for Biometry action cancel error")
            PowerAuthErrorCodes.BIOMETRY_NOT_SUPPORTED -> Log.d(TAG, "The device or operating system doesn't support biometric authentication.")
            PowerAuthErrorCodes.BIOMETRY_NOT_AVAILABLE -> Log.d(TAG, "The biometric authentication is temporarily unavailable.")
            PowerAuthErrorCodes.BIOMETRY_NOT_RECOGNIZED -> Log.d(TAG, "The biometric authentication did not recognize the biometric image") // Reported only during biometric authentication setup
            PowerAuthErrorCodes.BIOMETRY_NOT_ENROLLED -> Log.d(TAG, "The biometric authentication failed because there's no biometry enrolled")
            PowerAuthErrorCodes.BIOMETRY_LOCKOUT -> Log.d(TAG, "The biometric authentication is locked out due to too many failed attempts.")
            PowerAuthErrorCodes.OPERATION_CANCELED -> Log.d(TAG, "Error code for cancelled operations")
            PowerAuthErrorCodes.ENCRYPTION_ERROR -> Log.d(TAG, "Error code for errors related to end-to-end encryption")
            PowerAuthErrorCodes.INVALID_TOKEN -> Log.d(TAG, "Error code for errors related to token-based auth.")
            PowerAuthErrorCodes.INSUFFICIENT_KEYCHAIN_PROTECTION -> Log.d(TAG, "Device doesn't support requested keychain protection.")
            PowerAuthErrorCodes.PROTOCOL_UPGRADE -> Log.d(TAG, "Error code for error that occurs when protocol upgrade fails at unrecoverable error.")
            PowerAuthErrorCodes.PENDING_PROTOCOL_UPGRADE -> Log.d(TAG, "The operation is temporarily unavailable, due to pending protocol upgrade.")
            PowerAuthErrorCodes.TIME_SYNCHRONIZATION -> Log.d(TAG, "Failed to synchronize time with the server.")
            PowerAuthErrorCodes.WRONG_SIGNATURE -> Log.d(TAG, "Digital or JWS signature is not valid.")
            PowerAuthErrorCodes.UPGRADE_SDK -> Log.d(TAG, "Upgrade PowerAuth Mobile SDK in your application.")
            PowerAuthErrorCodes.OTHER -> Log.d(TAG, "Unspecified error.")
        }
        // Process additional information
        val additionalInfo = t.additionalInformation
        when (additionalInfo) {
            is BiometricErrorInfo -> {
                if (additionalInfo.isErrorPresentationRequired) {
                    //The application should display an error dialog after failed biometric authentication. This is relevant only
                    // if you disabled the biometric error dialog provided by PowerAuth mobile SDK.
                }
            }
        }
    }
    is ErrorResponseApiException -> {
        val errorResponse: Error? = t.errorResponse
        val httpResponseStatusCode = t.responseCode
        // Additional, optional objects assigned to the exception.
        val jsonResponseObject: JsonObject = t.responseJson
        val responseBodyString = t.responseBody
    }
    is FailedApiException -> {
        val httpStatusCode = t.responseCode
        // Additional, optional objects assigned to the exception.
        val jsonResponseObject: JsonObject = t.responseJson
        val responseBodyString = t.responseBody
    }
}
```

Note that you typically don't need to handle all error codes reported in the `PowerAuthErrorException`, or report all those situations to the user. Most of the codes are informational and help the developers properly integrate SDK into the application. A good example is `INVALID_ACTIVATION_STATE`, which typically means that your application's logic is broken and you're using PowerAuthSDK in an unexpected way.

Here's the list of important error codes, which the application should properly handle:

- `BIOMETRY_CANCEL` is reported when the user cancels the biometric authentication dialog
- `PROTOCOL_UPGRADE` is reported when SDK fails to upgrade itself to a newer protocol version. The code may be reported from `PowerAuthSDK.fetchActivationStatusWithCallback()`. This is an unrecoverable error resulting in the broken activation on the device, so the best situation is to inform the user about the situation and remove the activation locally.
- `PENDING_PROTOCOL_UPGRADE` is reported when the requested SDK operation cannot be completed due to a pending PowerAuth protocol upgrade. You can retry the operation later. The code is typically reported in situations when SDK is performing protocol upgrade in the background (as a part of activation status fetch), and the application wants to calculate the PowerAuth authentication code in parallel operation. Such kind of concurrency is forbidden since SDK version `1.0.0`


## Working with Invalid SSL Certificates

Sometimes, you may need to develop or test your application against a service that runs over HTTPS protocol with an invalid (self-signed) SSL certificate. By default, the HTTP client used in PowerAuth SDK communication validates the certificate. To disable the certificate validation, use a `PowerAuthSDK` initializer with a custom client configuration to initialize your PowerAuth SDK instance, like so:

```kotlin
// Set `HttpClientSslNoValidationStrategy as the default client SSL certificate validation strategy
val clientConfiguration = PowerAuthClientConfiguration.Builder()
    .clientValidationStrategy(HttpClientSslNoValidationStrategy())
    .build()
```

Be aware, that using this option will lead to the use of an unsafe implementation of `HostnameVerifier` and `X509TrustManager` SSL client validation. This is useful for debug/testing purposes only, e.g. when an untrusted self-signed SSL certificate is used on the server side.

It's strictly recommended to use this option only in debug flavors of your application. Deploying to production may cause a "Security alert" in the Google Developer Console. Please see [this](https://support.google.com/faqs/answer/7188426) and [this](https://support.google.com/faqs/answer/6346016) Google Help Center articles for more details. Beginning 1 March 2017, Google Play will block the publishing of any new apps or updates that use such unsafe implementation of `HostnameVerifier`.

How to solve this problem for debug/production flavors in the Gradle build script:

1. Define the boolean type `buildConfigField` in the flavor configuration.
   ```gradle
   productFlavors {
      production {
          buildConfigField 'boolean', 'TRUST_ALL_SSL_HOSTS', 'false'
      }
      debug {
          buildConfigField 'boolean', 'TRUST_ALL_SSL_HOSTS', 'true'
      }
   }
   ```

2. In code use this conditional initialization for the `PowerAuthClientConfiguration.Builder` builder.
   ```kotlin
   val clientBuilder = PowerAuthClientConfiguration.Builder()
   if (BuildConfig.TRUST_ALL_SSL_HOSTS) {
       clientBuilder.clientValidationStrategy(HttpClientSslNoValidationStrategy())
   }
   ```

3. Set `minifyEnabled` to true for release buildType to enable code shrinking with ProGuard.


## Debugging

The debug log is by default turned off. To turn it on, use the following code:

```kotlin
PowerAuthLog.setEnabled(true)
```

To turn on an even more detailed log, use the following code:

```kotlin
PowerAuthLog.setVerbose(true)
```

Note that it's highly recommended to turn on this feature only for the `DEBUG` build of your application. For example:

```kotlin
if (BuildConfig.DEBUG) {
    PowerAuthLog.setEnabled(true)
}
```

You can intercept the log and log it into your own report system, you can do so with `PowerAuthLogListener`.

```kotlin
PowerAuthLog.logListener = object : PowerAuthLogListener {
    override fun powerAuthDebugLog(message: String) {
        // Process debug log...
        // Note that the debug log is only reported when 
        // PowerAuthLog.setEnabled(true) is set.
        // We highly discourage using debug logs in production builds.
    }

    override fun powerAuthWarningLog(message: String) {
        // Process warning log...
    }

    override fun powerAuthErrorLog(message: String) {
        // Process error log...
    }
}
```

## Read Next

- [Additional Features](Additional-Features.md)
