# External Encryption Key

<!-- SIDEBAR _Sidebar.md -->
<!-- BREADCRUMB Android href=../PowerAuth-SDK-for-Android -->

<!-- begin box warning -->
Support for the External Encryption Key (EEK) was discontinued in PowerAuth Mobile SDK version 2.0.
<!-- end -->

In earlier SDK versions, `PowerAuthSDK` allowed you to specify an external encryption key (EEK) to provide an additional layer of protection for the knowledge and biometry factor keys. This mechanism was primarily used to create a chain of activations, where one primary `PowerAuthSDK` instance unlocked access to one or more secondary activations.

If the activation in your application is still using EEK, please use the following code at your application’s startup to remove it:

```kotlin
if (powerAuthSDK.hasExternalEncryptionKey()) {
    val eek = SecureData.copy(eekBytes)
    powerAuthSDK.removeExternalEncryptionKey(eek)
}
```

## Read Next

- [Synchronized Time](Synchronized-Time.md)
