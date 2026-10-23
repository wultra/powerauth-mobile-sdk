# Authentication Codes

## Symmetric Multi-Factor Authentication Code

To authenticate the request data, you need to first obtain user credentials (password, PIN code, biometric image) from the user. The task of obtaining the user credentials is used in more use-cases covered by the SDK. The core class is `PowerAuthAuthentication` that holds information about the used authentication factors:

```kotlin
// 1FA authentication code, uses device related key only.
val oneFactor = PowerAuthAuthentication.possession()

// 2FA authentication code - uses device related key and user PIN code.
val twoFactorPassword = PowerAuthAuthentication.possessionWithPassword("1234")

// 2FA authentication code, uses biometry factor-related key as a 2nd. factor.
// To obtain biometryFactorRelatedKey see "Fetching the Biometry Factor-Related Key for Authentication" chapter.
val twoFactorBiometry = PowerAuthAuthentication.possessionWithBiometry(biometryFactorRelatedKey)
```

When signing `POST`, `PUT` or `DELETE` requests, use request body bytes (UTF-8) as request data and the following code:

```kotlin
// 2FA authentication code - uses device related key and user PIN code
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")

// Compute authentication header for POST call with provided data made to URI with custom identifier "/payment/create"
try {
    val header = powerAuthSDK.authenticationHeaderForRequestWithBody(context, authentication, "POST", "/payment/create", requestBodyBytes)
    val httpHeaderKey = header.getKey()
    val httpHeaderValue = header.getValue()
} catch (e: PowerAuthErrorException) {
    // Handle error
}
```

When signing `GET` or `DELETE` request with query parameters, use the following code:

```kotlin
// 2FA authentication code - uses device-related key and user PIN code
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")

// Compute authentication header for GET call with provided query parameters made to URI with custom identifier "/payment/create"
val params = mapOf("param1" to "value1", "param2" to "value2")
try {
    val header = powerAuthSDK.authenticationHeaderForRequestWithParams(context, authentication, "GET", "/payment/create", params)
    val httpHeaderKey = header.getKey()
    val httpHeaderValue = header.getValue()
} catch (e: PowerAuthErrorException) {
    // Handle error
}
```

The result of the operation is appropriate HTTP header - you are responsible for hooking up the header value in your request correctly. The process with libraries like `OkHttp` goes like this:

```kotlin
// Prepare the request builder
val builder: Request.Builder = Builder().url(endpoint)

// Compute PowerAuth authentication header
try {
    val header = powerAuthSDK.authenticationHeaderForRequestWithBody(context, authentication, "POST", "/session/login", jsonBody)
    // Add HTTP header in the request builder
    builder.header(header.getKey(), header.getValue())
} catch (e: PowerAuthErrorException) {
    // Handle error
}

// Build the request, send it, and process the response...
// ...
```

### Request Synchronization

It is recommended that your application executes only one signed request at the time. The reason for that is that our scheme for authentication codes is using a counter as a representation of logical time. In other words, the order of request validation on the server is very important. If you issue more than one signed request at the same time, then the order is not guaranteed, and therefore one of the requests may fail. On top of that, Mobile SDK itself is using this type of authentication for its own purposes. For example, if you ask for token, then the SDK is using authenticated request to obtain the token's data. To deal with this problem, Mobile SDK is providing a custom serial `Executor`, which can be used for signed requests execution:

```kotlin
powerAuthSDK.serialExecutor.execute {
    // Recommended practice:
    // 1. You have to calculate the PowerAuth authentication header here.
    // 2. In case that you start yet another asynchronous operation from run(),
    //    then you have to wait for that operation's execution.
}
```

## Symmetric Offline Multi-Factor Authentication Code

This type of authentication is very similar to [Symmetric Multi-Factor Authentication Code](#symmetric-multi-factor-authentication-code) but the result is provided in the form of a simple, human-readable string (unlike the online version, where the result is an HTTP header). To calculate the code, you need a typical `PowerAuthAuthentication` object to define all required factors, nonce and data to sign. The `nonce` and `data` should also be transmitted to the application over the OOB channel (for example, by scanning a QR code). Then the authentication code calculation is straightforward:

```kotlin
// Prepare the authentication object
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")

powerAuthSDK.offlineAuthenticationCode(context, authentication, "/confirm/offline/operation", data, nonce, object: IOfflineAuthenticationCodeListener {
    override fun onOfflineAuthenticationCodeSucceed(authenticationCode: String) {
        Log.d(TAG, "Offline authentication code is: $authenticationCode")
    }

    override fun onOfflineAuthenticationCodeFailed(error: Throwable) {
        // Handle the error, such as biometric authentication cancel.
    }
})
```

The application has to show that calculated code to the user now, and the user has to re-type that code into the web application for the verification.

<!-- begin box info -->
You can alter the length of the code components by using `offlineAuthenticationCodeComponentLength()` function of `PowerAuthConfiguration.Builder` class.
<!-- end -->

## Read Next

- [Digital Signatures](Android-Digital-Signatures.md)
