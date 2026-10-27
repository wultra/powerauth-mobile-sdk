# Apple Watch Support

<!-- SIDEBAR _Sidebar.md -->
<!-- BREADCRUMB iOS href=../PowerAuth-SDK-for-iOS -->

This part of the documentation describes how to add support for Apple Watch to your PowerAuth-powered iOS application. This part of the documentation is not relevant to the **tvOS** platform.

## Prepare Watch Connectivity

The PowerAuth SDK for iOS uses the [WatchConnectivity framework](https://developer.apple.com/documentation/watchconnectivity) to achieve data synchronization between iPhone and Apple Watch devices. If you're not familiar with this framework, take a look at least at [WCSession](https://developer.apple.com/documentation/watchconnectivity/wcsession) and [WCSessionDelegate](https://developer.apple.com/documentation/watchconnectivity/wcsessiondelegate) interfaces before you start.

The PowerAuth SDK doesn't manage the state of the `WCSession` and it doesn't set the delegate to the session's singleton instance. It's up to you to properly configure and activate the default session, but the application has to cooperate with PowerAuth SDK to process the messages received from the counterpart device. To do this, PowerAuth SDKs on both sides are providing the `PowerAuthWCSessionManager` class which can help you process all incoming messages. Here's an example of how you can implement simple `SessionManager` for IOS:

```swift
import Foundation
import WatchConnectivity
import PowerAuth2

class SessionManager: NSObject, WCSessionDelegate {

    static let shared = SessionManager()

    private let session: WCSession? = WCSession.isSupported() ? WCSession.default : nil

    // Returns false, when the session is not available on the device.
    func activateSession() -> Bool {
        session?.delegate = self
        session?.activate()
        return session != nil
    }

    // MARK: - WCSessionDelegate

    func session(_ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: Error?) {
        if activationState == .activated {
            // now you can use WCSession for communication, send the status of the session to watch, etc...
        }
    }

    func sessionDidBecomeInactive(_ session: WCSession) {
        // session is now inactive
    }

    func sessionDidDeactivate(_ session: WCSession) {
        // session is now deactivated
    }

    func session(_ session: WCSession, didReceiveMessageData messageData: Data) {
        // Try to process PowerAuth messages...
        if PowerAuthWCSessionManager.sharedInstance.processReceivedMessageData(messageData, replyHandler: nil) {
            return // processed...
        }
        // Other SDKs or your own messages can be handled here...
        print("SessionManager.didReceiveMessageData did not process message.")
    }

    func session(_ session: WCSession, didReceiveMessageData messageData: Data, replyHandler: @escaping (Data) -> Void) {
        // Try to process PowerAuth messages...
        if PowerAuthWCSessionManager.sharedInstance.processReceivedMessageData(messageData, replyHandler: replyHandler) {
            return // processed...
        }
        // Other SDKs or your own messages can be handled here...
        print("SessionManager.didReceiveMessageData did not process message. Responding with empty data")
        replyHandler(Data())
    }

    func session(_ session: WCSession, didReceiveUserInfo userInfo: [String : Any] = [:]) {
        // Try to process PowerAuth messages...
        if PowerAuthWCSessionManager.sharedInstance.processReceivedUserInfo(userInfo) {
            return // processed...
        }
        // Other SDKs or your own messages can be handled here...
        print("SessionManager.didReceiveUserInfo did not process message.")
    }
}
```

<!-- begin box info -->
The code above is very similar to its [watchOS counterpart](../watchos/Configuration.md#prepare-watch-connectivity).
<!-- end -->

The example is implementing only a minimum set of methods from the `WCSessionDelegate` protocol to make message passing work. The important part is that at some point, both applications (iOS and watchOS) have to call `SessionManager.shared.activateSession()` to make the transfers possible. Once you activate your session on the device, you can use all APIs related to the communication.


## WCSession Activation Sequence

In this chapter, we will discuss the right initialization sequence for various interoperating objects during your application's startup. We recommend following those rules to make communication between iOS & watchOS reliable.

### Implementation Summary

On the application's startup:

1. Instantiate and configure all `PowerAuthSDK` instances especially ones to be synchronized with Apple Watch.
2. Activate `WCSession`, so get the default instance, assign your delegate, and call `activate()`
3. Wait for the session's activation in your delegate
4. Now you can use watch-related methods from PowerAuth SDK for iOS. For example, you can use a lazy method to send the status of activation to the watch device.

### Implementation Details

Due to our internal implementation details, each `PowerAuthSDK` instance is registered to `PowerAuthWCSessionManager` for incoming message processing. The registration is done in the object's designated init method, and the de-registration is automatic after the SDK object is destroyed. This technique works great but depends on the existence of the right object at the right time.

Once you activate `WCSession`, your `WCSessionDelegate` is going to receive messages (on the background thread) from the counterpart watch application. We are highlighting the importance of the right activation sequence because your watchOS application can wake up its iOS counterpart. Therefore, it is highly possible that some messages will be available right at the application's startup. If you don't follow the guidelines and forget to prepare your `PowerAuthSDK` instances before the `WCSession` is activated, then a couple of messages may be lost.

Fortunately, the situation on the watchOS side is much easier because all incoming messages are processed in one special service class, which is always available.


## Sending Activation Status to Watch

Before you start using PowerAuth on watchOS, it is recommended to send information about PowerAuth activation from iPhone to Apple Watch. The information transmitted to the watch is very limited. In fact, on the watchOS side, you can check only whether the activation on the iPhone is locally present or not. It is recommended to keep this status up to date as much as possible. That typically means that you may send the status every time you complete or remove the activation.

To send the current status of the activation, use the following code:

```swift
if !powerAuthSDK.sendActivationStatusToWatch() {
    // send message has not been issued, WCSession is probably not available / active
} else {
    // message has been issued and it's guaranteed that it will be delivered to the watch
}
```

There's also an asynchronous version, but the watch device has to be reachable at the time of the call:

```swift
powerAuthSDK.sendActivationStatusToWatch { (error) in
    if let error = error {
        // handle error, otherwise the transfer was OK
    }
}
```

<!-- begin box warning -->
Sending the status of the `PowerAuthSDK` instance that is currently without activation also effectively removes all associated tokens from Apple Watch.
<!-- end -->

## Sending Token to Watch

Once you have a `PowerAuthToken` object, use the following code to send it to the Apple Watch:

```swift
if let token = tokenStore.localToken(withName: "MyToken") {
    if !token.sendToWatch() {
        // send message has not been issued, WCSession is probably not available / active
    } else {
        // message has been issued and it's guaranteed that it will be delivered to the watch
    }
}
```

You can also use a different variant of the method with a completion block. However, you have to be sure that the Apple Watch is reachable at the time of call. Otherwise, the error is returned:

```swift
if let token = tokenStore.localToken(withName: "MyToken") {
    token.sendToWatch { (error) in
        if let error = error {
            // handle error, otherwise the transfer was OK
        }
    }
}
```

## Removing Token from Watch

You can remotely remove the token from a paired Apple Watch:

```swift
if let token = tokenStore.localToken(withName: "MyToken") {
    if !token.removeFromWatch() {
        // send message has not been issued, WCSession is probably not available / active
    } else {
        // message has been issued and it's guaranteed that it will be delivered to the watch
    }
}
```

There is also an asynchronous version, but the paired watch has to be reachable at the time of the call:

```swift
if let token = tokenStore.localToken(withName: "MyToken") {
    token.removeFromWatch { (error) in
        if let error = error {
            // handle error, otherwise the transfer was OK
        }
    }
}
```

## Read Next

- [External Encryption Key](External-Encryption-Key.md)
