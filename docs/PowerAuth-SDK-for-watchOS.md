# PowerAuth Mobile SDK for watchOS

<!-- begin remove -->
## Table of Contents

- [Installation](#installation)
   - [CocoaPods Installation](#cocoapods)
   - [Manual Installation](#manual)
- [SDK Configuration](#configuration)
   - [Prepare Watch Connectivity](#prepare-watch-connectivity)
   - [Configure PowerAuth for WatchKit](#configure-powerauth-for-watchkit)
- [Getting Device Activation Status](#getting-device-activation-status)
- [Token-Based Authentication](#token-based-authentication)
   - [Getting Token](#getting-token)
   - [Getting Token From iPhone](#getting-token-from-iphone)
   - [Generating Authorization Header](#generating-authorization-header)
   - [Removing Token Locally](#removing-token-locally)
   - [Removing Token From iPhone](#removing-tokenf-from-iphone)
- [Common SDK Tasks](#common-sdk-tasks)
- [Troubleshooting](#troubleshooting)

Related documents:

- [PowerAuth SDK for iOS](./PowerAuth-SDK-for-iOS.md) / or go directly to [Apple Watch section](./PowerAuth-SDK-for-iOS.md#apple-watch-support)
- [PowerAuth SDK for iOS App Extensions](./PowerAuth-SDK-for-iOS-Extensions.md)
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

### Manual

If you prefer not to use CocoaPods as dependency manager, you can integrate Watch SDK into your project manually as a git [submodule](http://git-scm.com/docs/git-submodule).

#### Git Submodules

The integration process is quite similar to integration of our library for IOS:

1. Open up the Terminal.app and go to your top-level project directory and add the library as a submodule:
    ```sh
    $ git submodule add https://github.com/wultra/powerauth-mobile-sdk.git PowerAuthLib
    $ git submodule update --init --recursive
    ```
    The first command will clone PowerAuth SDK into the `PowerAuthLib` folder and second will update all nested submodules. We're expecting that you already did this when you integrated PowerAuth into your application.

2. Open the new `PowerAuthLib` folder, and go to the `proj-xcode` sub-folder
3. Drag the `PowerAuthExtensionSdk.xcodeproj` project file into **Project Navigator** of your application's Xcode project. It should appear nested underneath your application's blue project icon.
4. Select your application project in the Project Navigator to navigate to the target configuration window and select the watch app's target under the **TARGETS** heading in the sidebar.
5. Now select **Build Phases** tab and expand **Target Dependencies** section. Click on the "Plus Sign" and choose **"PowerAuth2ForWatch"** framework from the **"PowerAuthExtensionSdk"** project.
6. Next, in the same **Build Phases** tab expand **Link With Libraries** section. Click on the "Plus Sign" and choose **"PowerAuth2ForWatch.framework"** from the **"PowerAuthExtensionSdk"** project.

## Configuration

The Watch SDK shares several source codes and configuration principles with the main iOS SDK. So, you can prepare the same set of constants as you're already using in your IOS application. The SDK provides just a limited functionality for the watch app (for example, you cannot create an activation or calculate a full PowerAuth signature from a watch application) and to do that it requires that your application's code will participate in data synchronization.

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
        let config = PowerAuthConfiguration(
            instanceId: Bundle.main.bundleIdentifier!,
            baseEndpointUrl: "https://localhost:8080/demo-server",
            configuration: "ARDDj6EB6iAUtNm...KKEcBxbnH9bMk8Ju3K1wmjbA==")

        return PowerAuthWatchSDK(configuration: config)!
    }

    // ... the rest of the controller's code ...
}
```

<!-- begin box warning -->
**IMPORTANT:** The configuration used above must match the configuration used in the IOS application otherwise `PowerAuthWatchSDK` instance will never be synchronized with its iOS counterpart. Take special care of the `instanceId` property, which **has to match with the value from iPhone**. By default, PowerAuth for iOS is using the application's bundle ID, so don't make a mistake and don't use the watchOS application's bundle identifier.
<!-- end -->

The Watch SDK doesn't provide a shared instance for the `PowerAuthWatchSDK` class and therefore you have to manage that instance on your own. The example above shows the beginning of the controller implementing a simple WatchKit scene. For all other code examples, we're going to use `self.powerAuthWatch` as a properly initialized instance of the `PowerAuthWatchSDK` object.


## Getting Device Activation Status

Unlike the iOS SDK, the Watch SDK provides only limited information about activation status. You can actually check only whether there's locally stored activation on iPhone, or not:

```swift
if self.powerAuthWatch.hasValidActivation() {
    // main application has a valid activation locally stored
}
```

The `hasValidActivation()` method is synchronous and reflects only the actual state stored locally on the Apple Watch. To get an update from your iPhone, you can use the following code:

```swift
// Lazy version

if !self.powerAuthWatch.updateActivationStatus() {
    // message has not been issued, WCSession is probably not available / active
} else {
    // message has been issued and it's guaranteed that it will be delivered to iPhone
    // The iPhone has to issue responses in a similar lazy way.
}

// Or asynchronous version...

self.powerAuthWatch.updateActivationStatus { (activationId, error) in
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
if let token = self.powerAuthWatch.tokenStore.localToken(withName: "MyToken") {
    // you have a token that can generate authorization headers
}
```

### Getting Token From iPhone

To get an access token already stored on the iPhone, you can use the following code:

```swift
self.powerAuthWatch.tokenStore.requestAccessToken(withName: "MyToken") { (token, error) in
    if let token = token {
        // the access token is valid
    } else {
        // an error occurred
    }
}
```

### Generating Authorization Header

Once you have a `PowerAuthToken` object, use the following code to generate an authorization header:

```swift
if let header = token.generateHeader() {
    let httpHeader = [ header.key : header.value ]
    // now you can attach that httpHeader to your HTTP request
} else {
    // in case of nil, the token is no longer valid
}
```

### Removing Token Locally

To remove the token locally, you can simply use the following code:

```swift
let tokenStore = self.powerAuthWatch.tokenStore
// Remove just one token
tokenStore.removeLocalToken(withName: "MyToken")
// Remove all local tokens
tokenStore.removeAllLocalTokens()
```

Note that removing tokens locally on a watch device does not affect the same tokens stored on an iPhone.

### Removing Token From iPhone

The token store available on watchOS exposes the `removeAccessToken()` method, but the implementation always returns the `PowerAuthErrorCode.invalidToken` error. This kind of operation is not supported.

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
