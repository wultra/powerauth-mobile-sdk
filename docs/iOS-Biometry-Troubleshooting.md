# Biometry Troubleshooting

## Biometry lockout

<!-- begin box warning -->
Note that if the biometric authentication fails with too many attempts in a row (e.g. biometry is locked out), then PowerAuth SDK will generate an invalid biometry factor-related key, and the success is reported back to the application. This is an intended behavior and as a result, it typically leads to unsuccessful authentication on the server and an increased counter of failed attempts. The purpose of this is to limit the number of attempts for attackers to deceive the biometry sensor.
<!-- end -->

## Thread-blocking operation

Be aware that if you try to calculate PowerAuth Symmetric Authentication Code with a biometric factor, then the call to the SDK function will block the calling thread while the biometric authentication dialog is displayed. So, it's not recommended to do such an operation on the main or the networking thread. For example:

```swift
let authentication = PowerAuthAuthentication.possessionWithBiometry()
let header = try? sdk.authenticationHeaderForRequestWithBody(with: authentication, method: "POST", uriId: "/some/uri-id", body: "{}".data(using: .utf8))
// The thread is blocked while the biometric dialog is displayed.
```

To avoid thread blocking, acquire the biometric key in advance:

```swift
powerAuthSDK.authenticateUsingBiometry(withPrompt: "Authenticate to sign in") { authentication, error in
    // callback is always called from the main thread
    if let authentication {
        // Success, you can use the provided PowerAuthAuthentication object for the authentication code calculation.
        // The provided authentication object is preconfigured for possession+biometry factors
    }
}
```

## Parallel biometric authentications

It's not recommended to calculate more than one authentication code with the biometric factor at the same time, or in a row at a quick pace. Both scenarios are considered an issue in the application's logic.

To prevent the first case, PowerAuth mobile SDK is using a global mutex that guarantees that only one attempt to get the biometry-protected data at the time is performed. If your application issues another signing operation while the system dialog is displayed, then this attempt ends with `.biometryCancel` error.

There's another similar issue on devices supporting FaceID. The FaceID technology behaves slightly differently than TouchID and if you try to use biometry too soon after a previous successful authentication, then the 2nd attempt will fail with an authentication error. This is undocumented, but we believe it's related to the animation presented to the user after successful authentication. You simply cannot request another biometric authentication while the animation is still playing.
 

## Use pre-authorized LAContext

If you want more control over the biometric authentication UI flow, then you can prepare `LAContext` and evaluate it on your own. The pre-authorized context can be then used to construct `PowerAuthAuthentication`:

```swift
let context = LAContext()
context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Please authenticate with biometry") { success, error in
    guard success && error == nil else {
        // Biometric error handling
        return
    }
    let authentication = PowerAuthAuthentication.possessionWithBiometry(context: context)
    // Now you can use the authentication object in any SDK function that accepts authentication with a biometric factor.
}
```

Be aware that the example above doesn't handle all quirks related to the PowerAuth protocol, so you should prefer to use the `authenticateUsingBiometry()` function instead:

```swift
let context = LAContext()
context.localizedReason = "Please authenticate with biometry"
powerAuthSDK.authenticateUsingBiometry(withContext: context) { authentication, error in
    guard let authentication = authentication else {
        if let nsError = error as? NSError {
            if nsError.powerAuthErrorCode == .biometryCancel {
                // cancel, app cancel, system cancel...
            } else if nsError.powerAuthErrorCode == .biometryFallback {
                // fallback button pressed
            }
            // If you're interested in the exact failure reason, then extract
            // the underlying LAError.
            if let laError = nsError.userInfo[NSUnderlyingErrorKey] as? LAError {
                // Investigate error codes...
            }
        }
        return
    }
    // Now use authentication in other APIs
}
```

## Read Next

- [Device Activation Removal](iOS-Device-Activation-Removal.md)
