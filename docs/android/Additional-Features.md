# Additional Features

<!-- SIDEBAR _Sidebar.md -->

PowerAuth SDK for Android contains multiple additional features that are useful for mobile apps.

## Obtaining User's Claims

If supported by the server, the PowerAuth mobile SDK can provide additional information asserted about a person associated with an activation. This information can be obtained either during the activation process or at a later time.

Here is an example of how to process user information during activation:

```kotlin
powerAuthSDK.createActivation(activation, object : ICreateActivationListener {
    override fun onActivationCreateSucceed(result: CreateActivationResult) {
        if (result.userInfo != null) {
            // User information received.
            // At this moment, the object is also available at
            // powerAuthSDK.lastFetchedUserInfo
        }
    }

    override fun onActivationCreateFailed(t: Throwable) {
        // Error handling
    }
})
```

To fetch the user information at a later time, use the following code:

```kotlin
val userInfo = powerAuthSDK.lastFetchedUserInfo
if (userInfo != null) {
    // User information is already available
} else {
    powerAuthSDK.fetchUserInfo(context, object : IUserInfoListener {
        override fun onUserInfoSucceed(userInfo: UserInfo) {
            // User information received
        }

        override fun onUserInfoFailed(t: Throwable) {
            // Error handling
        }
    })
}
```

The obtained `UserInfo` object contains the following properties:

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
| `isEmailVerified`       | `Boolean`| True if the user's email address has been verified, else false<sup>1</sup> |
| `phoneNumber`           | `String` | The user's preferred telephone number<sup>2</sup> |
| `isPhoneNumberVerified` | `Boolean`| True if the user's telephone number has been verified, else false<sup>1</sup> |
| `gender`                | `String` | The user's gender |
| `birthdate`             | `Date`   | The user's birthday |
| `zoneInfo`              | `String` | The user's time zone, e.g. `Europe/Paris` or `America/Los_Angeles` |
| `locale`                | `String` | The end-users locale, represented as a BCP47 language tag<sup>3</sup> |
| `address`               | `UserAddress` | The user's preferred postal address |
| `updatedAt`             | `Date`   | The time the user's information was last updated |
| `allClaims`             | `Map<String, Any>` | The full collection of claims received from the server |

If the `address` is provided, then `UserAddress` contains the following properties:

| Property                | Type     | Description |
|-------------------------|----------|-------------|
| `formatted`             | `String` | The full mailing address, with multiple lines if necessary |
| `street`                | `String` | The street address component, which may include house number, street name, post office box, and other multi-line information |
| `locality`              | `String` | City or locality component |
| `region`                | `String` | State, province, prefecture or region component |
| `postalCode`            | `String` | Zip code or postal code component |
| `country`               | `String` | Country name component |
| `allClaims`             | `Map<String, Any>` | Full collection of claims received from the server |

> Notes:
> 1. Value is false also when a claim is not present in the `allClaims` dictionary
> 2. Phone number is typically in E.164 format, for example `+1 (425) 555-1212` or `+56 (2) 687 2400`
> 3. This is typically an ISO 639-1 Alpha-2 language code in lowercase and an ISO 3166-1 Alpha-2 country code in uppercase, separated by a dash. For example, `en-US` or `fr-CA`

<!-- begin box info -->
Be aware that all properties in the `UserInfo` and `UserAddress` objects are optional and the availability of information depends on actual implementation on the server.
<!-- end -->


## Debug Build Detection

It is sometimes useful to switch PowerAuth SDK to a DEBUG build configuration to get more logs from the library. The DEBUG build is usually helpful during application development, but on the other hand, it's highly unwanted in production applications. For this purpose, the `PowerAuthSDK.hasDebugFeatures()` method provides information on whether the PowerAuth JNI library was compiled in the DEBUG configuration. It is a good practice to check this flag and crash the process when the production application is linked against the DEBUG PowerAuth:

```kotlin
if (!BuildConfig.DEBUG) {
    // You can also check your production build configuration
    if (powerAuthSDK.hasDebugFeatures()) {
        throw RuntimeException("Production app with DEBUG PowerAuth")
    }
}
```

## Request Interceptors

The `PowerAuthClientConfiguration` can contain multiple request interceptor objects, allowing you to adjust all HTTP requests created by SDK, before execution. Currently, you can use the following two classes:

- `BasicHttpAuthenticationRequestInterceptor` to add a basic HTTP authentication header to all requests
- `CustomHeaderRequestInterceptor` to add a custom HTTP header to all requests

For example:

```kotlin
val clientConfiguration = PowerAuthClientConfiguration.Builder()
    .requestInterceptor(BasicHttpAuthenticationRequestInterceptor("gateway-user", "gateway-password"))
    .requestInterceptor(CustomHeaderRequestInterceptor("X-CustomHeader", "123456"))
    .build()
```

We don't recommend implementing the `HttpRequestInterceptor` interface on your own. The interface allows you to tweak the requests created in the `PowerAuthSDK` but also gives you an opportunity to break things. So, rather than create your own interceptor, try to contact us and describe what's your problem with the networking in the PowerAuth SDK. Also, keep in mind that the interface may change in the future. We can guarantee the API stability of public classes implementing this interface, but not the stability of the interface itself.

## Custom User-Agent

The `PowerAuthClientConfiguration` contains the `userAgent` property that allows you to set a custom value for the "User-Agent" HTTP request header for all requests initiated by the library:

```kotlin
val clientConfiguration = PowerAuthClientConfiguration.Builder()
    .userAgent("MyApp/1.0.0")
    .build()
```

The default value of the property is composed as "APP-PACKAGE/APP-PACKAGE-VERSION PowerAuth2/PA-VERSION (OS/OS-VERSION, DEVICE-INFO)", for example: "com.test.app/1.0 PowerAuth2/1.7.0 (Android 11.0.0, SM-A525F)".

If you set `""` (empty string) to the `userAgent` property, then the default "User-Agent" provided by the operating system will be used. 

## Read Next

- [PowerAuth Mobile SDK for Android](../PowerAuth-SDK-for-Android.md)
