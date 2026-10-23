# Getting Device Activation Status

<!-- SIDEBAR _Sidebar.md -->

Unlike the iOS SDK, the Watch SDK provides only limited information about activation status. You can actually check only whether there's locally stored activation on iPhone, or not:

```swift
if powerAuthWatch.hasValidActivation() {
    // main application has a valid activation locally stored
}
```

The `hasValidActivation()` method is synchronous and reflects only the actual state stored locally on the Apple Watch. To get an update from your iPhone, you can use the following code:

```swift
// Lazy version

if !powerAuthWatch.updateActivationStatus() {
    // message has not been issued, WCSession is probably not available / active
} else {
    // message has been issued and it's guaranteed that it will be delivered to iPhone
    // The iPhone has to issue responses in a similar lazy way.
}

// Or asynchronous version...

powerAuthWatch.updateActivationStatus { (activationId, error) in
    let hasActivation = activationId != nil
    if error == nil {
        print("PowerAuth activation is: \(hasActivation ? "VALID" : "EMPTY") on iPhone")
    } else {
        // handle error...
    }
}
```

The asynchronous `updateActivationStatus` method can be used only if `WCSession` reports that the counterpart device is reachable.

## Read Next

- [Token-Based Authentication](Token-Based-Authentication.md)
