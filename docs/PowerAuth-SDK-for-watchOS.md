# PowerAuth Mobile SDK for watchOS

<!-- begin remove -->
## Table of Contents

- [Installation](#installation)
   - [CocoaPods Installation](#cocoapods)
- [SDK Configuration](#configuration)
   - [Prepare Watch Connectivity](#prepare-watch-connectivity)
   - [Configure PowerAuth for WatchKit](#configure-powerauth-for-watchkit)
- [Getting Device Activation Status](#getting-device-activation-status)
- [Token-Based Authentication](#token-based-authentication)
   - [Getting Token](#getting-token)
   - [Getting Token From iPhone](#getting-token-from-iphone)
   - [Generating Authentication Header](#generating-authentication-header)
   - [Removing Token Locally](#removing-token-locally)
   - [Removing Token From iPhone](#removing-tokenf-from-iphone)
- [Common SDK Tasks](#common-sdk-tasks)
- [Troubleshooting](#troubleshooting)

Related documents:

- [PowerAuth SDK for iOS](./PowerAuth-SDK-for-iOS.md) / or go directly to [Apple Watch section](./PowerAuth-SDK-for-iOS.md#apple-watch-support)
<!-- end -->

## Installation

This chapter describes how to get PowerAuth SDK for watchOS up and running in your app. In the current version, you can choose between CocoaPods and manual library integration. Both types of installation will lead to your watchOS application linked with a dynamic library, provided by the `PowerAuth2ForWatch.[xc]framework`.

To distinguish between SDKs, the following short terms will be used in this document:

- **iOS SDK**, as short term for *PowerAuth SDK for iOS*
- **Watch SDK** as short term for *PowerAuth SDK for watchOS*

### CocoaPods

[CocoaPods](http://cocoapods.org) is a dependency manager for Cocoa projects. You can install it with the following command:

```bash
$ gem install cocoapods
```

To integrate the PowerAuth library into your Xcode project using CocoaPods, specify it in your `Podfile`:

```ruby
target 'YourAppTarget' do
  platform :ios, '11.0'
  pod 'PowerAuth2'
end

target 'YourWatchAppTarget' do
  platform :watchos, '4.0'
  pod 'PowerAuth2ForWatch'
end
```

Then, run the following command:

```bash
$ pod install
```

<!-- begin box info -->
Check [troubleshooting section](#cocoapods-integration-fails) of this document when `pod update` or `pod install` doesn't work.
<!-- end -->

## Configuration

The Watch SDK shares several source codes and configuration principles with the main iOS SDK. So, you can prepare similar set of constants as you're already using in your main iOS application. The SDK provides just a limited functionality for the watch app (for example, you cannot create an activation or calculate a full PowerAuth authentication code from a watch application) and to do that it requires that your application's code will participate in data synchronization.

### Prepare Watch Connectivity

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
The code above is very similar to its [iOS counterpart](./PowerAuth-SDK-for-iOS.md#prepare-watch-connectivity).
<!-- end -->

The example above is implementing only a minimum set of methods from the `WCSessionDelegate` protocol to make message passing work. You also have to implement a very similar class for your IOS application. The important part is that at some point, both applications (iOS and watchOS) have to call `SessionManager.shared.activateSession()` to make the transfers possible. Once you activate your session on the device, you can use all APIs related to the communication.


### Configure PowerAuth for WatchKit

The configuration of PowerAuth SDK for watchOS is pretty straightforward:

```swift
import PowerAuth2ForWatch

class InterfaceController: WKInterfaceController {

    // Lazy initialized variable
    private var powerAuthWatch: PowerAuthWatchSDK = {
        return InterfaceController.setupPowerAuth()
    }()

    private static func setupPowerAuth() -> PowerAuthWatchSDK {
        let config = PowerAuthConfiguration(instanceId: "your.ios.app.instanceId")
        return PowerAuthWatchSDK(configuration: config)!
    }

    // ... the rest of the controller's code ...
}
```

<!-- begin box warning -->
**IMPORTANT:** The configuration used above must match the configuration used in the iOS application otherwise `PowerAuthWatchSDK` instance will never be synchronized with its iOS counterpart. Take special care of the `instanceId` property, which **has to match with the value from iPhone**. By default, PowerAuth for iOS is using the application's bundle ID, so don't make a mistake and don't use the watchOS application's bundle identifier.
<!-- end -->

The Watch SDK doesn't provide a shared instance for the `PowerAuthWatchSDK` class and therefore you have to manage that instance on your own. The example above shows the beginning of the controller implementing a simple WatchKit scene. For all other code examples, we're going to use `powerAuthWatch` as a properly initialized instance of the `PowerAuthWatchSDK` object.


## Getting Device Activation Status

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

## Token-Based Authentication

WARNING: Before you start using access tokens, please visit our [wiki page for powerauth-crypto](https://github.com/wultra/powerauth-crypto/blob/develop/docs/MAC-Token-Based-Authentication.md) for more information about this feature. You can also visit the documentation about tokens available in [PowerAuth SDK for iOS](./PowerAuth-SDK-for-iOS.md#token-based-authentication).

The basic principles for working with tokens on watchOS are the same as for iOS applications, so the interface is practically identical to what you know from PowerAuth SDK for iOS. The main difference is that the watchOS application cannot ask the PowerAuth server to create a new token, but as a replacement, it can ask for a token already stored on the iPhone. In fact, from the point of the watchOS application's view, the iOS application is just a kind of "remote server" providing tokens.

### Getting Token

To get an access token already stored on the watch device, you can use the following code:

```swift
if let token = powerAuthWatch.tokenStore.localToken(withName: "MyToken") {
    // you have a token that can generate authentication headers
}
```

### Getting Token From iPhone

To get an access token already stored on the iPhone, you can use the following code:

```swift
powerAuthWatch.tokenStore.requestAccessToken(withName: "MyToken") { (token, error) in
    if let token = token {
        // the access token is valid
    } else {
        // an error occurred
    }
}
```

### Generating Authentication Header

Use the following code to generate an authentication header:

```swift
let task = powerAuthWatch.tokenStore.generateAuthenticationHeader(withName: "MyToken") { header, error in
    if let header = header {
        let httpHeader = [ header.key : header.value ]
        // now you can attach that httpHeader to your HTTP request
    } else {
        // failure, the token is no longer valid, or failed to synchronize time
        // with the server.
    }
}
```

Once you have a `PowerAuthToken` object, then you can use also a synchronous code to generate an authentication header:

```swift
if let header = token.generateHeader() {
    let httpHeader = [ header.key : header.value ]
    // now you can attach that httpHeader to your HTTP request
} else {
    // in case of nil, the token is no longer valid
}
```

<!-- begin box warning -->
The synchronous example above is safe to use only if you're sure that the time is already [synchronized with the server](#synchronized-time).
<!-- end -->


### Removing Token Locally

To remove the token locally, you can simply use the following code:

```swift
let tokenStore = powerAuthWatch.tokenStore
// Remove just one token
tokenStore.removeLocalToken(withName: "MyToken")
// Remove all local tokens
tokenStore.removeAllLocalTokens()
```

Note that removing tokens locally on a watch device does not affect the same tokens stored on an iPhone.

### Removing Token From iPhone

The token store available on watchOS exposes the `removeAccessToken()` method, but the implementation always returns the `PowerAuthErrorCode.invalidToken` error. This kind of operation is not supported.

## Synchronized Time

The PowerAuth mobile SDK internally uses time synchronized with the PowerAuth Server for its cryptographic functions, such as [Generating Authentication Header](#generating-authentication-header). The synchronized time can also be beneficial for your application. For example, if you want to display a time-sensitive message or countdown to your users, you can take advantage of this service.

Use the following code to get the service responsible for the time synchronization: 

```swift
let timeService = powerAuthWatch.timeSynchronizationService
```

### Automatic Time Synchronization

The time is synchronized automatically in the following situations:

- When a token header is being calculated using the asynchronous API.

### Manually Synchronize Time

Use the following code to synchronize the time manually:

```swift
let task = timeService.synchronizeTime(callback: { error in
    if error == nil {
        // Success, time has been properly synchronized
    } else {
        // Failed to synchronize the time
    }
}, callbackQueue: .main)
```

### Get Synchronized Time

To get the synchronized time, use the following code:

```swift
if timeService.isTimeSynchronized {
    // Get synchronized timestamp
    let timestamp = timeService.currentTime()
    // If a date object is required, then use the following snippet
    let date = Date(timeIntervalSince1970: timestamp)
} else {
    // Time is not synchronized yet. If you call currentTime() then 
    // the returned timestamp is similar to Date().timeIntervalSince1970
    let timestamp = timeService.currentTime()
}
```

The time service provides additional information about time, such as how precisely the time is synchronized with the server:

```swift
if timeService.isTimeSynchronized {
    let precision = timeService.localTimeAdjustmentPrecision
    print("Time is synchronized with precision \(precision)")
}
```

The precision value represents a maximum absolute deviation of synchronized time against the actual time on the server. For example, a value `0.5` means that the time provided by the `currentTime()` method may be 0.5 seconds ahead or behind the actual time on the server. If the precision is not sufficient for your purpose, for example, if you need to display a real-time countdown in your application, then try to synchronize the time manually. The precision basically depends on how quickly is the synchronization response received and processed from the server. A faster response results in higher precision.


## Common SDK Tasks

### Error Handling

You can follow the same practices as for iOS SDK because the Watch SDK codebase shares the same error constants with a full PowerAuth SDK for iOS.

### Debug Build Detection

It is sometimes useful to switch Watch SDK to a DEBUG build configuration, to get more logs from the library:

- **CocoaPods:** we currently don't provide DEBUG pod. This will be resolved in some future versions of Watch SDK.
- **Manual installation:** Xcode matches build configuration across all nested projects, so you usually don't need to care about the configuration switching.

The DEBUG build is usually helpful during the application development, but on the other side, it's highly unwanted in production applications. For this purpose, the `PowerAuthSystem.isInDebug()` method provides information on whether the PowerAuth for the watchOS library was compiled in the DEBUG configuration. It is a good practice to check this flag and crash the process when the production application is linked against the DEBUG library:

```swift
#if YOUR_APPSTORE_BUILD_FLAG
    // Final vs Debug library trap
    if PowerAuthSystem.isInDebug() {
        fatalError("CRITICAL ERROR: You're using Debug PowerAuth library in production build.")
    }
#endif
```

## Troubleshooting

This section of the document contains various workarounds and tips for Watch SDK usage.

### WCSession Activation Sequence on iOS

You should check recommendations about [WCSession's activation sequence on iOS](./PowerAuth-SDK-for-iOS.md#wcsession-activation-sequence).

### Cocoapods Integration Fails

In case `pod update` fails on various errors, try the following workarounds:

- Update your pod tool at first:
  ```bash
  $ echo before `pod --version`
  $ sudo gem install cocoapods
  $ echo after  `pod --version`
  ```

- To reveal more details about the problem, try to run an update with a verbose switch:
  ```bash
   $ pod update --verbose
  ```

- Clean your pod cache. You can remove one specific pod from the cache, or clean it all:
  ```bash
  $ pod cache clean PowerAuth2
  $ pod cache clean PowerAuth2ForWatch
  $ pod cache clean PowerAuth2ForExtensions
  $ pod cache clean --all
  ```

- Try to run `pod update` for twice. The Cocoapods tool is a mystery and sometimes just doesn't work as you would expect.
