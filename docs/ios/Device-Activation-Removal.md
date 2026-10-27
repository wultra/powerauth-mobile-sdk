# Device Activation Removal

<!-- SIDEBAR _Sidebar.md -->
<!-- BREADCRUMB iOS href=../PowerAuth-SDK-for-iOS -->

You can remove activation using several ways - the choice depends on the desired behavior.

## Simple Device-Only Removal

You can clear activation data anytime from the Keychain. The benefit of this method is that it does not require help from the server, and the user does not have to be logged in. The issue with this removal method is simple: The activation still remains active on the server side. This, however, does not have to be an issue in your case.

To remove only data related to PowerAuth SDK for iOS, use the `PowerAuthKeychain` class:

```swift
powerAuthSDK.removeActivationLocal()
```

## Removal via Authenticated Session

Suppose your server uses an authenticated session to keep the users logged in. In that case, you can combine the previous method with calling your proprietary endpoint to remove activation for the currently logged-in user. The advantage of this method is that activation does not remain active on the server. The issue is that the user has to be logged in (the session must be active and must have an activation ID stored) and that you have to publish your own method to handle this use case.

The code for this activation removal method is as follows:

```swift
// Use custom call to proprietary server endpoint to remove activation.
// The user must be logged in at this moment, so that the session can find
// associated activation ID
self.httpClient.post(null, "/custom/activation/remove") { (error) in
    if error == nil {
        powerAuthSDK.removeActivationLocal()
    } else {
        // Report error
    }
}

```

## Removal via Signed Request

PowerAuth Standard RESTful API has a dedicated endpoint for activation removal. This endpoint uses a authentication header verification for looking up the activation to be removed. The benefit of this method is that it is already present in both PowerAuth SDK for iOS and PowerAuth Standard RESTful API - nothing has to be programmed. Also, the user does not have to be logged in to use it. However, the user has to authenticate using 2FA with either a password or biometry.

Use the following code for an activation removal using a signed request:

```swift
// 2FA authentication code - uses device-related key and user PIN code
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

// Remove activation using the provided authentication object
powerAuthSDK.removeActivation(with: auth) { (error) in
    if error == nil {
        // OK, activation was removed
    } else {
        // Report error to user
    }
}
```

<!-- begin box info -->
Depending on server support and configuration, it's possible to remove the activation with 1FA authentication (e.g. using `PowerAuthAuthentication.possession()`).
<!-- end -->

## Rename via Signed Request

PowerAuth Standard RESTful API also provides an activation rename endpoint. The SDK signs the request before encrypting it in the activation scope. The operation requires 2FA, so use possession with password or possession with biometry; possession-only authentication is rejected locally. The callback returns the server-confirmed activation name.

```swift
let auth = PowerAuthAuthentication.possessionWithPassword(password: "1234")

powerAuthSDK.renameActivation(name: "John's iPhone", authentication: auth) { activationName, error in
    if let activationName = activationName {
        // Server-confirmed activation name
    } else {
        // Report error to user
    }
}
```

## Read Next

- [End-To-End Encryption](End-To-End-Encryption.md)
