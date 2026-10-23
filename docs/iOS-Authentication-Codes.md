# Authentication Codes

<!-- SIDEBAR _Sidebar_iOS.md -->

## Symmetric Multi-Factor Authentication Code

This type of data authentication is suitable for online operations, such as login, new payment, or confirming changes in settings, and allows you to sign data in HTTP request.

To sign request data, you need to first obtain user credentials (password, PIN code, Touch ID scan) from the user. The task of obtaining the user credentials is used in more use cases covered by the SDK. The core class is `PowerAuthAuthentication` that holds information about the used authentication factors:

```swift
// 1FA authentication code - uses device-related key only.
let oneFactor = PowerAuthAuthentication.possession()

// 2FA authentication code - uses device-related key and user PIN code.
let twoFactorPassword = PowerAuthAuthentication.possessionWithPassword(password: "1234")

// 2FA authentication code - uses biometry factor-related key as a 2nd. factor.
let task = powerAuthSDK.authenticateUsingBiometry(withPrompt: "Please authenticate with biometry to log-in.") { authentication, error in
    if let authentication {
        // the returned authentication object is ready to use for the authentication code calculation
    } else {
        // Failure, cast object to NSError
        guard let error = error as? NSError else {
            fatalError() // Should never happen
        }
        if error.powerAuthErrorCode == .biometryCancel {
            // user canceled the operation
        } else {
            // other errors...
        }
    }
}
// In case the biometric authentication is no longer relevant (for example, you have a limited time to complete the operation), 
// then you can cancel the returned task.
task.cancel()
```

When signing `POST`, `PUT`, or `DELETE` requests, use request body bytes (UTF-8) as request data and the following code:

```swift
// 2FA authentication code - uses device-related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

// Sign POST call with provided data made to URI with custom identifier "/payment/create"
do {
    let header = try powerAuthSDK.authenticationHeaderForRequestWithBody(with: auth, method: "POST", uriId: "/payment/create", body: requestBodyData)
    let httpHeaderKey = header.key
    let httpHeaderValue = header.value
} catch _ {
    // In case of invalid configuration, invalid activation state, or corrupted state data
}
```

When signing `GET` or `DELETE` request with query parameters, use the following code:

```swift
// 2FA authentication code - uses device-related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

// Sign GET call with provided query parameters made to URI with custom identifier "/payment/create"
let params = [
    "param1": "value1",
    "param2": "value2"
]

do {
    let header = try powerAuthSDK.authenticationHeaderForRequestWithParams(with: auth, method: "GET", uriId: "/payment/create", params: params)
    let httpHeaderKey = header.key
    let httpHeaderValue = header.value
} catch _ {
    // In case of invalid configuration, invalid activation state, or corrupted state data
}
```

### Request Synchronization

It is recommended that your application executes only one signed request at a time. The reason for that is that our authentication code scheme uses a counter as a representation of logical time. In other words, the order of request validation on the server is very important. If you issue more than one signed request at the same time, then the order is not guaranteed, and therefore one of the requests may fail. On top of that, Mobile SDK itself is using this type of authentication for its purposes. For example, if you ask for a token, then the SDK is using a signed request to obtain the token's data. To deal with this problem, Mobile SDK is providing a few methods that help with the signed requests synchronization.

If your networking is based on `OperationQueue`, then you can add your own `Operation` objects directly to the internal queue. Be aware that the PowerAuth authentication code must be calculated as a part of the operation's execution. For example:

```swift
let httpOperation: Operation = YourHttpOperation(...)
guard powerAuthSDK.executeOperation(onSerialQueue: httpOperation) else {
    fatalError("There's no activation")
}
```

In the case of custom networking, you can use the method to execute any block on the serial queue. In this case, the PowerAuth authentication code must be calculated as a part of the block's execution. For example:

```swift
powerAuthSDK.executeBlock(onSerialQueue: { internalTask in
    yourNetworking.post(yourRequest, completionHandler: { (data, response, error) in
        // Your response processing...
        // No matter what happens, you have to call the task.cancel() at the end
        internalTask.cancel()
    }, cancelationHandler: {
        // In case that your networking cancels the request, the given task
        // must be also canceled
        internalTask.cancel()
    })
})
```

## Symmetric Offline Multi-Factor Authentication Code

This type of authentication is very similar to [Symmetric Multi-Factor Authentication Code](#symmetric-multi-factor-authentication-code), but the result is provided in the form of a simple, human-readable string (unlike the online version, where the result is an HTTP header). To calculate the code, you need a typical `PowerAuthAuthentication` object to define all required factors, nonce, and data to sign. The `nonce` and `data` should also be transmitted to the application over the OOB channel (for example, by scanning a QR code). Then the authentication code calculation is straightforward:

```swift
// 2FA authentication - uses device-related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

_ = powerAuthSDK.offlineAuthenticationCode(with: auth, uriId: "/confirm/offline/operation", body: data, nonce: nonce) { authenticationCode, error in 
    if let authenticationCode {
        print("authentication code is " + authenticationCode)
    }
}
```

The application has to show that calculated code to the user now, and the user has to re-type that code into the web application for verification. 

<!-- begin box info -->
You can alter the length of the code components in the `offlineAuthenticationCodeComponentLength` property of the `PowerAuthConfiguration` object.
<!-- end -->

## Read Next

- [Digital Signatures](iOS-Digital-Signatures.md)
