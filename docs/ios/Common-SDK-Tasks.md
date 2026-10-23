# Common SDK Tasks

<!-- SIDEBAR _Sidebar.md -->

## Error Handling

Most of the SDK methods return an error object of an `NSError` class in case something goes wrong. Of course, it is your responsibility to handle the errors these objects represent. There are two ways how you can obtain an error object from PowerAuth SDK for iOS.

In most cases, you receive an error object via a callback, like in this example:

```swift
powerAuthSDK.fetchActivationStatus { (status, error) in
    // Handle 'error' here
}
```

In other cases, you receive an error via an exception, like in this example:

```swift
do {
    let header = try powerAuthSDK.authenticationHeaderForRequestWithBody(with: auth, method: "POST", uriId: "/payment/create", body: requestBodyData)
} catch let error as NSError {
    // Handle 'error' here
}
```

<!-- begin box info -->
The original Objective-C code uses a method with the `BOOL` return type that passes `NSError**` (pointer to error object) as a method parameter. This syntax is automatically converted to exceptions when using code in Swift.
<!-- end -->

Errors that are caused by PowerAuth SDK for iOS use the `PowerAuthErrorDomain` and `PowerAuthErrorCode` enumeration available via the `NSError.powerAuthErrorCode` property. Use these values to determine the type of error. In principle, all errors should be handled in a very similar manner. Use this code snippet for inspiration:

```swift
if error == nil {
    // No error happened
} else {
    // Handle the error
    if let error = error as NSError? {

        // If yes, handle the error based on the error code
        switch error.powerAuthErrorCode {
        
        case .NA:
            print("Error has different domain than PowerAuthErrorDomain")
            
        case .networkError:
            print("Error code for error with network connectivity or download")
            if let errorResponse = error.powerAuthRestApiErrorResponse {
                // Error response is available only if actual response was received from the server.
                let httpStatusCode = errorResponse.httpStatusCode
                // Error code & message received from the server. If server is down and returns 500, then values
                // may not be available.
                let errorCode = errorResponse.responseObject?.code
                let errorMessage = errorResponse.responseObject?.message
            }

        case .signatureError:
            print("Error code for error in signature calculation")

        case .invalidActivationState:
            print("Error code for error that occurs when activation state is invalid")
        
        case .invalidActivationCode:
            print("Error code for error that occurs when activation code is invalid")
            
        case .invalidActivationData:
            print("Error code for error that occurs when activation data is invalid")

        case .missingActivation:
            print("Error code for error that occurs when activation is required but missing")

        case .activationPending:
            print("Error code for error that occurs when pending activation is present and work with completed activation is required")

        case .biometryNotAvailable:
            print("Error code for TouchID/FaceID not available error")

        case .biometryCancel:
            print("Error code for TouchID/FaceID action cancel error")
        
        case .biometryFallback:
            print("Error code for TouchID/FaceID fallback action")
            
        case .biometryFailed:
            print("Error code for TouchID/FaceID action failure")

        case .operationCancelled:
            print("Error code for cancelled operations")

        case .encryption:
            print("Error code for errors related to end-to-end encryption")
            
        case .wrongParameter:
            print("Error code for general API misuse")

        case .invalidToken:
            print("Error code for errors related to token based auth.")

        case .watchConnectivity:
            print("Error code for errors related to synchronization between iOS and watchOS.")

        case .protocolUpgrade:
            print("Error code for error that occurs when protocol upgrade fails at unrecoverable error.")

        case .pendingProtocolUpgrade:
            print("The operation is temporarily unavailable, due to pending protocol upgrade.")

        case .externalPendingOperation:
            print("Other application is doing activation or protocol upgrade.")
            
        case .timeSynchronization:
            print("Failed to synchronize time with the server.")

        case .wrongSignature:
            print("Digital or JWS signature is not valid.")

        case .upgradeSDK:
            print("Upgrade PowerAuth Mobile SDK in your application.")

        case .other:
            print("Unspecified error.")
            
        default:
            print("Unknown error")
        }
    }
}
```

Note that you typically don't need to handle all error codes reported in the `Error` object, or report all those situations to the user. Most of the codes are informational and help the developers properly integrate SDK into the application. A good example is `PowerAuthErrorCode.invalidActivationState`, which typically means that your application's logic is broken and you're using PowerAuthSDK in an unexpected way.

Here's the list of important error codes, which the application should properly handle:

- `PowerAuthErrorCode.biometryCancel` is reported when the user cancels the biometric authentication dialog
- `PowerAuthErrorCode.biometryFallback` is reported when the user cancels the biometric authentication dialog with a fallback button
- `PowerAuthErrorCode.pendingProtocolUpgrade` is reported when the requested SDK operation cannot be completed due to a pending PowerAuth protocol upgrade. You can retry the operation later. The error code is typically reported in situations when SDK is performing protocol upgrade and the application wants to calculate the PowerAuth authentication code in parallel operation. Such kind of concurrency is forbidden since SDK version `1.0.0`
- `PowerAuthErrorCode.externalPendingOperation` is reported when the requested operation collides with the same operation type already started in the external application.
- `PowerAuthErrorCode.upgradeSDK` is reported when the local activation data format is not understandable by this version of PowerAuth Mobile SDK.

## Working with Invalid SSL Certificates

Sometimes, you may need to develop or test your application against a service that runs over HTTPS protocol with an invalid (self-signed) SSL certificate. By default, the HTTP client used in PowerAuth SDK communication validates the certificate. To disable the certificate validation, add the following code just before your `PowerAuthSDK` instance configuration:

```swift
// Create a custom  `PowerAuthClientConfiguration` object:
let clientConfig = PowerAuthClientConfiguration()
clientConfig.sslValidationStrategy = PowerAuthClientSslNoValidationStrategy()
// configure the PowerAuthSDK object
let powerAuthSDK = PowerAuthSDK(
    configuration: PowerAuthConfiguration(...),
    biometricConfiguration: nil, // optional, default will be used when nil
    clientConfiguration: clientConfig
)
```

## Logs

<!-- begin box warning -->
Note that the functions below are effective only if PowerAuth SDK is compiled in the `DEBUG` build configuration or the `ENABLE_PA2_LOG` compilation flag is set.
<!-- end -->

Logs are turned off by default. To turn it on, use the following code:

```swift
PowerAuthLogSetEnabled(true)
```

To turn on an even more detailed log, use the following code:

```swift
PowerAuthLogSetVerbose(true)
```

You can intercept the log and log it into your own report system, you can do so with `PowerAuthLogDelegate`.

```swift
import PowerAuth2

class MyClass: PowerAuthLogDelegate {

    init {
        // Only works in DEBUG build or when 
        // ENABLE_PA2_LOG compilation flag is set
        PowerAuthLogSetEnabled(true)
        #if DEBUG
        // verbose logging should be used only in debug builds
        // as it can contain sensitive information
        PowerAuthLogSetVerbose(true)
        #endif
        PowerAuthLogSetDelegate(self)
    }
    
    // MARK: - PowerAuthLogDelegate implementation
    
    func powerAuthLog(_ log: String) {
        // Process the log (write to file for example)
    }
}
```

If you're handling logs with the `PowerAuthLogDelegate`, you might want to turn off the default console logs. To do so, use:

```swift
PowerAuthLogToConsoleSetEnabled(false)
```

## Read Next

- [Additional Features](Additional-Features.md)
