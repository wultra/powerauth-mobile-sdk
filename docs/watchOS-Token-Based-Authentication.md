# Token-Based Authentication

<!-- SIDEBAR _Sidebar_watchOS.md -->

WARNING: Before you start using access tokens, please visit our [wiki page for powerauth-crypto](https://github.com/wultra/powerauth-crypto/blob/develop/docs/MAC-Token-Based-Authentication.md) for more information about this feature. You can also visit the documentation about tokens available in [PowerAuth SDK for iOS](iOS-Token-Based-Authentication.md).

The basic principles for working with tokens on watchOS are the same as for iOS applications, so the interface is practically identical to what you know from PowerAuth SDK for iOS. The main difference is that the watchOS application cannot ask the PowerAuth server to create a new token, but as a replacement, it can ask for a token already stored on the iPhone. In fact, from the point of the watchOS application's view, the iOS application is just a kind of "remote server" providing tokens.

## Getting Token

To get an access token already stored on the watch device, you can use the following code:

```swift
if let token = powerAuthWatch.tokenStore.localToken(withName: "MyToken") {
    // you have a token that can generate authentication headers
}
```

## Getting Token From iPhone

To get an access token already stored on the iPhone, you can use the following code:

```swift
powerAuthWatch.tokenStore.requestAccessToken(withName: "MyToken") { (token, error) in
    if let token = token {
        // the access token is valid
    } else {
        // an error occurred
    }
}
```

## Generating Authentication Header

Use the following code to generate an authentication header:

```swift
let task = powerAuthWatch.tokenStore.generateAuthenticationHeader(withName: "MyToken") { header, error in
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
The synchronous example above is safe to use only if you're sure that the time is already [synchronized with the server](watchOS-Synchronized-Time.md).
<!-- end -->


## Removing Token Locally

To remove the token locally, you can simply use the following code:

```swift
let tokenStore = powerAuthWatch.tokenStore
// Remove just one token
tokenStore.removeLocalToken(withName: "MyToken")
// Remove all local tokens
tokenStore.removeAllLocalTokens()
```

Note that removing tokens locally on a watch device does not affect the same tokens stored on an iPhone.

## Removing Token From iPhone

The token store available on watchOS exposes the `removeAccessToken()` method, but the implementation always returns the `PowerAuthErrorCode.invalidToken` error. This kind of operation is not supported.

## Read Next

- [Synchronized Time](watchOS-Synchronized-Time.md)
