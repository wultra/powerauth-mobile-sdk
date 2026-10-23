# Device Activation Removal

<!-- SIDEBAR _Sidebar_Android.md -->

You can remove activation using several ways - the choice depends on the desired behavior.

## Simple Device-Only Removal

You can clear activation data anytime from the `SharedPreferences`. The benefit of this method is that it does not require help from the server, and the user does not have to be logged in. The issue with this removal method is simple: The activation still remains active on the server side. This, however, does not have to be an issue in your case.

To remove only data related to PowerAuth SDK for Android, use the following code:

```kotlin
powerAuthSDK.removeActivationLocal(context)
```

## Removal via Authenticated Session

Suppose your server uses an authenticated session to keep the users logged in. In that case, you can combine the previous method with calling your proprietary endpoint to remove activation for the currently logged-in user. The advantage of this method is that activation does not remain active on the server. The issue is that the user has to be logged in (the session must be active and must have an activation ID stored) and that you have to publish your own method to handle this use case.

The code for this activation removal method is as follows:

```kotlin
// Use custom call to proprietary server endpoint to remove activation.
//The user must be logged in at this moment, so that the session can find
// associated activation ID
this.httpClient.post(null, "/custom/activation/remove", object: ICustomListener {
    override fun onSucceed() {
        powerAuthSDK.removeActivationLocal(context)
    }
    
    override fun onFailed(t: Throwable) {
        // Error occurred, report it to the user
    }
})
```

## Removal via Signed Request

PowerAuth Standard RESTful API has a dedicated endpoint for activation removal. This endpoint uses a authentication code verification for looking up the activation to be removed. The benefit of this method is that it is already present in both PowerAuth SDK for Android and PowerAuth Standard RESTful API - nothing has to be programmed. Also, the user does not have to be logged in to use it. However, the user has to authenticate using 2FA with either password or biometric authentication.

Use the following code for an activation removal using a signed request:

```kotlin
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")

// Remove activation using the provided authentication object
powerAuthSDK.removeActivationWithAuthentication(context, authentication, object: IActivationRemoveListener {
    override fun onActivationRemoveSucceed() {
        // OK, activation was removed
    }

    override fun onActivationRemoveFailed(t: Throwable) {
        // Report error to user
    }
})
```

<!-- begin box info -->
Depending on server support and configuration, it's possible to remove the activation with 1FA authentication (e.g. using `PowerAuthAuthentication.possession()`).
<!-- end -->

## Rename via Signed Request

PowerAuth Standard RESTful API also provides an activation rename endpoint. The SDK signs the request before encrypting it in the activation scope. The operation requires 2FA, so use possession with password or possession with biometry; possession-only authentication is rejected locally. The callback returns the server-confirmed activation name.

```kotlin
val authentication = PowerAuthAuthentication.possessionWithPassword("1234")

powerAuthSDK.renameActivationWithAuthentication(context, authentication, "John's Android", object: IActivationRenameListener {
    override fun onActivationRenameSucceed(activationName: String) {
        // Server-confirmed activation name
    }

    override fun onActivationRenameFailed(t: Throwable) {
        // Report error to user
    }
})
```

## Read Next

- [End-To-End Encryption](Android-End-To-End-Encryption.md)
