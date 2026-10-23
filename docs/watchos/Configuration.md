# SDK Configuration

<!-- SIDEBAR _Sidebar.md -->

The Watch SDK shares several source codes and configuration principles with the main iOS SDK. So, you can prepare similar set of constants as you're already using in your main iOS application. The SDK provides just a limited functionality for the watch app (for example, you cannot create an activation or calculate a full PowerAuth authentication code from a watch application) and to do that it requires that your application's code will participate in data synchronization.

## Prepare Watch Connectivity

The PowerAuth SDK for watchOS is using [the WatchConnectivity framework](https://developer.apple.com/documentation/watchconnectivity) to achieve data synchronization between iPhone and Apple Watch devices. If you're not familiar with this framework, then please take a look at least at [WCSession](https://developer.apple.com/documentation/watchconnectivity/wcsession) and [WCSessionDelegate](https://developer.apple.com/documentation/watchconnectivity/wcsessiondelegate) interfaces, before you start.

The Watch SDK doesn't manage the state of `WCSession` and doesn't set the delegate to the session's singleton instance. It's up to you to properly configure and activate the session, but the application has to cooperate with our SDK to process the messages received from the counterpart device. To do this, PowerAuth SDKs on both sides are providing the `PowerAuthWCSessionManager` class which can process all incoming messages. Here's an example of how you can implement your simple `SessionManager` for watchOS:

```swift
import Foundation
import WatchConnectivity
import PowerAuth2ForWatch

class SessionManager: NSObject, WCSessionDelegate {

    static let shared = SessionManager()

    private let session: WCSession = WCSession.default

    func activateSession() {
        session.delegate = self
        session.activate()
    }

    // MARK: - WCSessionDelegate

    func session(_ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: Error?) {
        if activationState == .activated {
            // now you can use WCSession object for communication
        }
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
The code above is very similar to its [iOS counterpart](../ios/Apple-Watch-Support.md#prepare-watch-connectivity).
<!-- end -->

The example above is implementing only a minimum set of methods from the `WCSessionDelegate` protocol to make message passing work. You also have to implement a very similar class for your IOS application. The important part is that at some point, both applications (iOS and watchOS) have to call `SessionManager.shared.activateSession()` to make the transfers possible. Once you activate your session on the device, you can use all APIs related to the communication.


## Configure PowerAuth for WatchKit

The configuration of PowerAuth SDK for watchOS is pretty straightforward:

```swift
import PowerAuth2ForWatch

class InterfaceController: WKInterfaceController {

    // Lazy initialized variable
    private var powerAuthWatch: PowerAuthWatchSDK = {
        return InterfaceController.setupPowerAuth()
    }()

    private static func setupPowerAuth() -> PowerAuthWatchSDK {
        do {
            let config = PowerAuthConfiguration(instanceId: "your.ios.app.instanceId")
            return try PowerAuthWatchSDK(configuration: config)
        } catch {
            // Failed to create PowerAuthWatchSDK
        }
    }

    // ... the rest of the controller's code ...
}
```

<!-- begin box warning -->
**IMPORTANT:** The configuration used above must match the configuration used in the iOS application otherwise `PowerAuthWatchSDK` instance will never be synchronized with its iOS counterpart. Take special care of the `instanceId` property, which **has to match with the value from iPhone**. By default, PowerAuth for iOS is using the application's bundle ID, so don't make a mistake and don't use the watchOS application's bundle identifier.
<!-- end -->

The Watch SDK doesn't provide a shared instance for the `PowerAuthWatchSDK` class and therefore you have to manage that instance on your own. The example above shows the beginning of the controller implementing a simple WatchKit scene. For all other code examples, we're going to use `powerAuthWatch` as a properly initialized instance of the `PowerAuthWatchSDK` object.

## Read Next

- [Getting Device Activation Status](Getting-Device-Activation-Status.md)
