# Token-Based Authentication

<!-- begin box warning -->
**WARNING:** Before you start using access tokens, please visit our [wiki page for powerauth-crypto](https://github.com/wultra/powerauth-crypto/blob/develop/docs/MAC-Token-Based-Authentication.md) for more information about this feature.
<!-- end -->

The tokens are simple, locally cached objects, producing timestamp-based authentication headers. Be aware that tokens are NOT a replacement for general PowerAuth Authentication Codes. They are helpful in situations when the codes are too heavy or too complicated for implementation. Each token has the following properties:

- It needs a PowerAuth Authentication Code for its creation (e.g., you need to provide a `PowerAuthAuthentication` object)
- It has a unique identifier on the server. This identifier is not exposed to the public API, but you can reveal that value in the debugger.
- It has a symbolic name (e.g., "MyToken") defined by the application programmer to identify already created tokens.
- It can generate timestamp-based authentication HTTP headers.
- It can be used concurrently. Token's private data doesn't change over time.
- The token is associated with the `PowerAuthSDK` instance. So, you can use the same symbolic name in multiple SDK instances, and each created token will be unique.
- Tokens are persisted in the `KeychainFactory` service and cached in the memory.
- Once the parent `PowerAuthSDK` instance loses its activation, all its tokens are removed from the local database.

## Getting Token

To get an access token, you can use the following code:

```kotlin
// 1FA authentication - uses device-related key
val authentication = PowerAuthAuthentication.possession()
val cancelableTask = powerAuthSDK.tokenStore.requestAccessToken(context, "MyToken", authentication, object: IGetTokenListener {
    override fun onGetTokenSucceeded(powerAuthToken: PowerAuthToken) {
        // the token has been successfully acquired
    }

    override fun onGetTokenFailed(throwable: Throwable) {
        // an error occurred
    }
})
```

The request is performed synchronously or asynchronously depending on whether the token is locally cached on the device. You can test this situation by calling `tokenStore.hasLocalToken(context, "MyToken")`. If the operation is asynchronous, then `requestAccessToken()` returns a cancellable task.

## Generating Authentication Header
Use the following code to generate an authentication header:

```kotlin
val task = tokenStore.generateAuthenticationHeader(context, "MyToken", object : IGenerateTokenHeaderListener {
    override fun onGenerateTokenHeaderSucceeded(header: PowerAuthHttpHeader) {
        val httpHeaderKey = header.key
        val httpHeaderValue = header.value
    }

    override fun onGenerateTokenHeaderFailed(t: Throwable) {
        // Failure
    }
})
```

Once you have a `PowerAuthToken` object, then you can use also a synchronous code to generate an authentication header:

```kotlin
try {
    val header = token.generateTokenHeader()
    val httpHeaderKey = header.key
    val httpHeaderValue = header.value
} catch (e: PowerAuthErrorException) {
    // Handle error
}
```

<!-- begin box warning -->
The synchronous example above is safe to use only if you're sure that the time is already [synchronized with the server](Android-Synchronized-Time.md).
<!-- end -->

## Removing Token From the Server

To remove the token from the server, you can use the following code:

```kotlin
powerAuthSDK.tokenStore.removeAccessToken(context, "MyToken", object: IRemoveTokenListener {
    override fun onRemoveTokenSucceeded() {
        Log.d(TAG, "Token has been removed")
    }

    override fun onRemoveTokenFailed(t: Throwable) {
        // handle HTTP error
    }
})
```

## Removing Token Locally

To remove the token locally, you can simply use the following code:

```kotlin
// Remove just one token
powerAuthSDK.tokenStore.removeLocalToken(context, "MyToken")
// Remove all local tokens
powerAuthSDK.tokenStore.removeAllLocalTokens(context)
```

Note that by removing tokens locally, you will lose control of the tokens stored on the server.

## Read Next

- [Authenticated Protocol Upgrade](Android-Authenticated-Protocol-Upgrade.md)
