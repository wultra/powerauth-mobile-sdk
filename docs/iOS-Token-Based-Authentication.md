# Token-Based Authentication

<!-- SIDEBAR _Sidebar_iOS.md -->

<!-- begin box warning -->
**WARNING:** Before you start using access tokens, please visit our [documentation for powerauth-crypto](https://github.com/wultra/powerauth-crypto/blob/develop/docs/MAC-Token-Based-Authentication.md) for more information about this feature.
<!-- end -->

The tokens are simple, locally cached objects, producing timestamp-based authentication headers. Be aware that tokens are NOT a replacement for general PowerAuth Authentication Codes. They are helpful in situations when the authentication codes are too heavy or too complicated for implementation. Each token has the following properties:

- It needs a PowerAuth authentication code for its creation (e.g., you need to provide `PowerAuthAuthentication` object)
- It has a unique identifier on the server. This identifier is not exposed to the public API, but the DEBUG version of SDK can reveal that identifier in the debugger (e.g., you can use `po tokenObject` to print the object's description)
- It has a symbolic name (e.g. "MyToken") defined by the application programmer to identify already created tokens.
- It can generate timestamp-based authentication HTTP headers.
- It can be used concurrently. Token's private data doesn't change over time.
- The token is associated with the `PowerAuthSDK` instance. So, you can use the same symbolic name in multiple SDK instances, and each created token will be unique.
- Tokens are persisted in the keychain and cached in the memory.
- Once the parent `PowerAuthSDK` instance loses its activation, all its tokens are removed from the local database.

## Getting Token

To get an access token, you can use the following code:

```swift
// 1FA authentication code - uses device-related key
let auth = PowerAuthAuthentication.possession()

let tokenStore = powerAuthSDK.tokenStore

let task = tokenStore.requestAccessToken(withName: "MyToken", authentication: auth) { (token, error) in
    if let token = token {
        // now you can generate a header
    } else {
        // handle error
    }
}
```

The request is performed synchronously or asynchronously depending on whether the token is locally cached on the device. You can test this situation by calling `tokenStore.hasLocalToken(withName: "MyToken")`. If an operation is asynchronous, then `requestAccessToken()` returns a cancellable task.

## Generating Authentication Header

Use the following code to generate an authentication header:

```swift
let task = tokenStore.generateAuthenticationHeader(withName: "MyToken") { header, error in
    if let header = header {
        let httpHeader = [ header.key : header.value ]
        // now you can attach that httpHeader to your HTTP request
    } else {
        // failure, the token is no longer valid, or failed to synchronize time
        // with the server.
    }
}
```

Once you have a `PowerAuthToken` object, then you can use also a synchronous code to generate an authentication header:

```swift
if let header = token.generateHeader() {
    let httpHeader = [ header.key : header.value ]
    // now you can attach that httpHeader to your HTTP request
} else {
    // in case of nil, the token is no longer valid
}
```

<!-- begin box warning -->
The synchronous example above is safe to use only if you're sure that the time is already [synchronized with the server](iOS-Synchronized-Time.md).
<!-- end -->


## Removing Token From the Server

To remove the token from the server, you can use the following code:

```swift
let tokenStore = powerAuthSDK.tokenStore
tokenStore.removeAccessToken(withName: "MyToken") { (removed, error) in
    if removed {
        // token has been removed
    } else {
        // handle error
    }
}
```

## Removing Token Locally

To remove the token locally, you can simply use the following code:

```swift
let tokenStore = powerAuthSDK.tokenStore
// Remove just one token
tokenStore.removeLocalToken(withName: "MyToken")
// Remove all local tokens
tokenStore.removeAllLocalTokens()
```

Note that by removing tokens locally, you will lose control of the tokens stored on the server.

## Read Next

- [Authenticated Protocol Upgrade](iOS-Authenticated-Protocol-Upgrade.md)
