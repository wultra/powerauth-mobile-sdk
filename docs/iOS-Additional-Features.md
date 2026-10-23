# Additional Features

PowerAuth SDK for iOS contains multiple additional features that are useful for mobile apps.

## Obtaining User's Claims

If supported by the server, the PowerAuth mobile SDK can provide additional information asserted about a person associated with an activation. This information can be obtained either during the activation process or at a later time.

Here is an example of how to process user information during activation:

```swift
powerAuthSDK.createActivation(activation) { (result, error) in
    if let result {
        if let userInfo = result.userInfo {
            // User information received.
            // At this moment, the object is also available at
            // powerAuthSDK.lastFetchedUserInfo
        }
    } else {
        // Error handling
    }
}
```

To fetch the user information at a later time, use the following code:

```swift
if let userInfo = powerAuthSDK.lastFetchedUserInfo {
    // User information is already available
} else {
    sdk.fetchUserInfo { userInfo, error in
        if let userInfo {
            // User information received
        } else {
            // Error handling
        }
    }
}
```

The obtained `PowerAuthUserInfo` object contains the following properties:

| Property                | Type     | Description |
|-------------------------|----------|-------------|
| `subject`               | `String` | The user's identifier |
| `name`                  | `String` | The full name of the user |
| `givenName`             | `String` | The given or first name of the user |
| `familyName`            | `String` | The surname(s) or last name(s) of the user |
| `middleName`            | `String` | The middle name of the user |
| `nickname`              | `String` | The casual name of the user |
| `preferredUsername`     | `String` | The username by which the user wants to be referred to at the application |
| `profileUrl`            | `String` | The URL of the profile page for the user |
| `pictureUrl`            | `String` | The URL of the profile picture for the user |
| `websiteUrl`            | `String` | The URL of the user's web page or blog |
| `email`                 | `String` | The user's preferred email address |
| `isEmailVerified`       | `Bool`   | True if the user's email address has been verified, else false<sup>1</sup> |
| `phoneNumber`           | `String` | The user's preferred telephone number<sup>2</sup> |
| `isPhoneNumberVerified` | `Bool`   | True if the user's telephone number has been verified, else false<sup>1</sup> |
| `gender`                | `String` | The user's gender |
| `birthdate`             | `Date`   | The user's birthday |
| `zoneInfo`              | `String` | The user's time zone, e.g. `Europe/Paris` or `America/Los_Angeles` |
| `locale`                | `String` | The end-users locale, represented as a BCP47 language tag<sup>3</sup> |
| `address`               | `PowerAuthUserAddress` | The user's preferred postal address |
| `updatedAt`             | `Date`   | The time the user's information was last updated |
| `allClaims`             | `[String : Any]` | The full collection of standard claims received from the server |

If the `address` is provided, then `PowerAuthUserAddress` contains the following properties:

| Property                | Type     | Description |
|-------------------------|----------|-------------|
| `formatted`             | `String` | The full mailing address, with multiple lines if necessary |
| `street`                | `String` | The street address component, which may include house number, street name, post office box, and other multi-line information |
| `locality`              | `String` | City or locality component |
| `region`                | `String` | State, province, prefecture or region component |
| `postalCode`            | `String` | Zip code or postal code component |
| `country`               | `String` | Country name component |
| `allClaims`             | `[String : Any]` | Full collection of standard claims received from the server |

> Notes:
> 1. Value is false also when the claim is not present in the `allClaims` dictionary
> 2. Phone number is typically in E.164 format, for example `+1 (425) 555-1212` or `+56 (2) 687 2400`
> 3. This is typically an ISO 639-1 Alpha-2 language code in lowercase and an ISO 3166-1 Alpha-2 country code in uppercase, separated by a dash. For example, `en-US` or `fr-CA`

<!-- begin box info -->
Be aware that all properties in the `PowerAuthUserInfo` and `PowerAuthUserAddress` objects are optional and the availability of information depends on actual implementation on the server.
<!-- end -->

## Password Strength Indicator

Choosing a weak passphrase in applications with high-security demands can be potentially dangerous. You can use our [Wultra Passphrase Meter](https://github.com/wultra/passphrase-meter) library to estimate the strength of the passphrase and warn the user when he tries to use such a passphrase in your application.

## Debug Build Detection

It is sometimes useful to switch PowerAuth SDK to a DEBUG build configuration to get more logs from the library:

- **CocoaPods:** A majority of the SDK is distributed as source codes, so it will match your application's build configuration. Only low-level C++ codes and several wrapper classes on top of those are precompiled into a static library.
- **Manual installation:** Xcode matches build configuration across all nested projects, so you usually don't need to care about the configuration switching.

The DEBUG build is usually helpful during application development, but on the other hand, it's highly unwanted in production applications. For this purpose, the `PowerAuthSystem.isInDebug()` method provides information on whether the PowerAuth library was compiled in DEBUG configuration. It is a good practice to check this flag and crash the process when the production application is linked against the DEBUG PowerAuth:

```swift
#if YOUR_APPSTORE_BUILD_FLAG
    // Final vs Debug library trap
    if PowerAuthSystem.isInDebug() {
        fatalError("CRITICAL ERROR: You're using Debug PowerAuth library in production build.")
    }
#endif
```

## Request Interceptors

The `PowerAuthClientConfiguration` can contain multiple request interceptor objects, allowing you to adjust all HTTP requests created by the SDK before their execution. Currently, you can use the following two classes:

- `PowerAuthBasicHttpAuthenticationRequestInterceptor` to add a basic HTTP authentication header to all requests
- `PowerAuthCustomHeaderRequestInterceptor` to add a custom HTTP header to all requests

For example:

```swift
let basicAuth = PowerAuthBasicHttpAuthenticationRequestInterceptor(username: "gateway-user", password: "gateway-password")
let customHeader = PowerAuthCustomHeaderRequestInterceptor(headerKey: "X-CustomHeader", value: "123456")
let clientConfig = PowerAuthClientConfiguration()
clientConfig.requestInterceptors = [ basicAuth, customHeader ]
```

We don't recommend implementing the `PowerAuthHttpRequestInterceptor` protocol on your own. The interface allows you to tweak the requests created in the `PowerAuthSDK` but also gives you an opportunity to break things. So, rather than create your own interceptor, contact us and describe what use case is missing. Also, keep in mind that the interface may change in the future. We can guarantee the API stability of public classes implementing this interface, but not the stability of the interface itself.

## Custom User-Agent

The `PowerAuthClientConfiguration` contains the `userAgent` property that allows you to set a custom value for the "User-Agent" HTTP request header for all requests initiated by the library:

```swift
let clientConfig = PowerAuthClientConfiguration()
clientConfig.userAgent = "MyClient/1.0.0"
```

The default value of the property is composed as "APP-EXECUTABLE/APP-VERSION PowerAuth2/PA-VERSION (OS/OS-VERSION, DEVICE-INFO)", for example: "MyApp/1.0 PowerAuth2/1.7.0 (iOS 15.2, iPhone12.1)". The information about the application executable and version is obtained from the main bundle and its `Info.plist`.

If you set `nil` to the `userAgent` property, then the default "User-Agent" provided by the operating system will be used. 

## Read Next

- [Troubleshooting](iOS-Troubleshooting.md)
