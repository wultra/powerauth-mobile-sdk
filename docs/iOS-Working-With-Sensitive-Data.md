# Working with sensitive data

<!-- SIDEBAR _Sidebar_iOS.md -->

The PowerAuth mobile SDK is using the `PowerAuthSecureData` object to manage the cryptographically sensitive data, such as encryption keys. You can encounter this object in several public API functions, such as functions for [Secure Vault](iOS-Secure-Vault.md). This chapter explains how to use the `PowerAuthSecureData` object properly.

## Create an instance of `PowerAuthSecureData`

If you need to provide cryptographically sensitive key material to PowerAuth mobile SDK, then use the following code:

```swift
let yourKey = "nbuSR123nbuSR123".data(using: .ascii)!
let secureData = PowerAuthSecureData(withData: yourKey)
```

The `secureData` object will keep copy of bytes. In case you also wants to destroy the content of source `Data` structure, then you can try an alternative constructor, that try to erase content of the source data in case the source data is instance of `NSMutableData` class:

```swift
let mutableKey = NSMutableData(data: "nbuSR123nbuSR123".data(using: .ascii)!) as Data
let secureData = PowerAuthSecureData(withDataAndClearSource: mutableKey)
```

As you can see, this unlikely happens in typical Swift projects, so you may ensure on your own that data is erased properly:

```swift
extension Data {
    mutating func secureErase() {
        resetBytes(in: 0..<count)   // Fill with zeroes
        removeAll(keepingCapacity: false) // Release memory
    }
}

var yourKey = "nbuSR123nbuSR123".data(using: .ascii)!
let secureData = PowerAuthSecureData(withData: yourKey)
yourKey.secureErase()
```

## Using an instance of `PowerAuthSecureData`

To get reference to stored bytes, use the following code:

```swift
func processSecureData(secureData: PowerAuthSecureData) {
    doSomethingWitBytes(secureData.sensitiveData)
}
```

<!-- begin box warning -->
Be aware that you should not keep the reference to provided `Data` object. If you need to keep the bytes longer, then keep the reference to `SecureData` instance, or make your own copy of bytes, returned in `data` property.
<!-- end -->

## Read Next

- [Biometry Setup](iOS-Biometry-Setup.md)
