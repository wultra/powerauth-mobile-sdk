# Working with sensitive data

The PowerAuth mobile SDK is using `SecureData` class for manage the cryptographically sensitive data, such as encryption keys. You can encounter this class in several public API functions, such as functions for [Secure Vault](Android-Secure-Vault.md). This chapter explains how to use the `SecureData` object properly.

## Create instance of `SecureData`

If you need to provide cryptographically sensitive key material to PowerAuth mobile SDK, then use the following code:

```kotlin
val yourKey = "nbuSR123nbuSR123".toByteArray()
val secureData = SecureData.copy(yourKey)
```

The `secureData` object will keep copy of bytes. In case you also wants to erase also the content of the source array, then you can use an alternative construction:

```kotlin
val yourKey = "nbuSR123nbuSR123".toByteArray()
val secureData = SecureData.copyAndClearSource(yourKey)
```

Finally, if you're sure that no other object retains reference to the byte array (for example, if it's returned as a result of encrypt or decrypt function), then you can use the following construction:

```kotlin
val yourKey = "nbuSR123nbuSR123".toByteArray()
val secureData = SecureData.capture(yourKey)
```

## Using instance of `SecureData`

To get reference to stored bytes, use the following code:

```swift
func processSecureData(secureData: SecureData) {
    doSomethingWitBytes(secureData.sensitiveData)
}
```

<!-- begin box warning -->
Be aware that you should not keep the reference to provided byte array. If you need to keep the bytes longer, then keep the reference to `SecureData` instance, or make your own copy of bytes, returned in `sensitiveData` property.
<!-- end -->

## Read Next

- [Biometric Authentication Setup](Android-Biometric-Authentication-Setup.md)
