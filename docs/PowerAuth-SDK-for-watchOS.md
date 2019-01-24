# PowerAuth Mobile SDK for Apple Watch

## Table of Contents

- [Installation](#installation)
   - [CocoaPods Installation](#cocoapods)
   - [Manual Installation](#manual)
- [SDK Configuration](#configuration)
   - [Prepare Watch Connectivity](#prepare-watch-connectivity)
   - [Configure PowerAuth for WatchKit](#configure-powerauth-for-watchkit)
- [Getting Device Activation Status](#getting-device-activation-status)
- [Token Based Authentication](#token-based-authentication)
   - [Getting token](#getting-token)
   - [Getting token from iPhone](#getting-token-from-iphone)
   - [Generating authorization header](#generating-authorization-header)
   - [Removing token locally](#removing-token-locally)
- [Common SDK Tasks](#common-sdk-tasks)
- [Troubleshooting](#troubleshooting)

Related documents:

- [PowerAuth SDK for iOS](./PowerAuth-SDK-for-iOS.md) / or go directly to [Apple Watch section](./PowerAuth-SDK-for-iOS.md#apple-watch-support)
- [PowerAuth SDK for iOS App Extensions](./PowerAuth-SDK-for-iOS-Extensions.md)


## Installation

This chapter describes how to get PowerAuth SDK for watchOS up and running in your app. In current version, you can choose between CocoaPods and manual library integration. Both types of installation will lead to your watchOS application linked with a static library, provided by the `PowerAuth2ForWatch.framework`. Unlike the PowerAuth for iOS, the watch SDK supports bitcode.

To distinguish between SDKs, the following short terms will be used in this document:

- **iOS SDK**, as short term for *PowerAuth SDK for iOS*
- **Watch SDK** as short term for *PowerAuth SDK for watchOS*

### CocoaPods

[CocoaPods](http://cocoapods.org) is a dependency manager for Cocoa projects. You can install it with the following command:
```bash
$ gem install cocoapods
```

To integrate PowerAuth library into your Xcode project using CocoaPods, specify it in your `Podfile`:
```ruby
target 'YourAppTarget' do
  platform :ios, '8.0'
  pod 'PowerAuth2'
end

target 'YourWatchAppTarget' do
  platform :watchos, '2.0'
  pod 'PowerAuth2ForWatch'
end

# Disable bitcode for iOS targets (see iOS integration for details)
post_install do |installer|
  installer.pods_project.targets.each do |target|
    if target.platform_name == :ios
      puts "Disabling bitcode for target  #{target.name}"
      target.build_configurations.each do |config|
        config.build_settings['ENABLE_BITCODE'] = 'NO'
      end
    end
  end
end
```

Then, run the following command:
```bash
$ pod install
```

*Note: Check [troubleshooting section](#cocoapods-integration-fails) of this document when `pod update` or `pod install` doesn't work.*

### Manual

If you prefer not to use CocoaPods as dependency manager, you can integrate Watch SDK into your project manually as a git [submodule](http://git-scm.com/docs/git-submodule).

#### Git submodules

The integration process is quite similar to integration of our library for IOS:

1. Open up Terminal.app and go to your top-level project directory and add the library as a submodule:
    ```sh
    $ git submodule add https://github.com/wultra/powerauth-mobile-sdk.git PowerAuthLib
    $ git submodule update --init --recursive
    ```
    First command will clone PowerAuth SDK into `PowerAuthLib` folder and second, will update all nested submodules. We're expecting that you already did this when you integrated PowerAuth into your application.

2. Open the new `PowerAuthLib` folder, and go to `proj-xcode` sub-folder
3. Drag the `PowerAuthExtensionSdk.xcodeproj` project file into **Project Navigator** of your application's Xcode project. It should appear nested underneath your application's blue project icon.
4. Select your application project in the Project Navigator to navigate to the target configuration window and select the watch app's target under the **TARGETS** heading in the sidebar.
5. Now select **Build Phases** tab and expand **Target Dependencies** section. Click on the "Plus Sign" and choose **"PowerAuth2ForWatch"** framework from the **"PowerAuthExtensionSdk"** project.
6. Next, in the same **Build Phases** tab expand **Link With Libraries** section. Click on the "Plus Sign" and choose **"PowerAuth2ForWatch.framework"** from the **"PowerAuthExtensionSdk"** project.



## Configuration

The Watch SDK shares several source codes and configuration principles with main iOS SDK. So, you can prepare the same set of constants as you're already using in your IOS application. The SDK provides just a limited functionality for watch app (for example, you cannot create an activation or calculate a full PowerAuth signature from a watch application) and to do that it requires that your application's code will participate on data synchronization.

### Prepare Watch Connectivity

The PowerAuth SDK for watchOS is using [WatchConnectivity framework](https://developer.apple.com/documentation/watchconnectivity) to achieve data synchronization between iPhone and Apple Watch devices. If you're not familiar with this framework, then please take a look at least at [WCSession](https://developer.apple.com/documentation/watchconnectivity/wcsession) and [WCSessionDelegate](https://developer.apple.com/documentation/watchconnectivity/wcsessiondelegate) interfaces, before you start.

The Watch SDK doesn't manage state of `WCSession` and doesn't set delegate to the session's singleton instance. It's up to you to properly configure and activate the session, but the application has to cooperate with our SDK to process the messages received from counterpart device. To do this, PowerAuth SDKs on both sides are providing `PA2WCSessionManager` class which can process all incoming messages. Here's an example, how you can implement your simple `SessionManager` for watchOS:

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
        if PA2WCSessionManager.sharedInstance.processReceivedMessageData(messageData, replyHandler: nil) {
            return // processed...
        }
        // Other SDKs, or your own messages can be handler here...
        print("SessionManager.didReceiveMessageData did not process message.")
    }

    func session(_ session: WCSession, didReceiveMessageData messageData: Data, replyHandler: @escaping (Data) -> Void) {
        // Try to process PowerAuth messages...
        if PA2WCSessionManager.sharedInstance.processReceivedMessageData(messageData, replyHandler: replyHandler) {
            return // processed...
        }
        // Other SDKs, or your own messages can be handler here...
        print("SessionManager.didReceiveMessageData did not process message. Responding with empty data")
        replyHandler(Data())
    }

    func session(_ session: WCSession, didReceiveUserInfo userInfo: [String : Any] = [:]) {
        // Try to process PowerAuth messages...
        if PA2WCSessionManager.sharedInstance.processReceivedUserInfo(userInfo) {
            return // processed...
        }
        // Other SDKs, or your own messages can be handler here...
        print("SessionManager.didReceiveUserInfo did not process message.")
    }
}
```

*Note that the code above is very similar to its [iOS counterpart](./PowerAuth-SDK-for-iOS.md#prepare-watch-connectivity)*

The example above is implementing only a minimum set of methods from `WCSessionDelegate` protocol to make message passing work. You also have to implement a very similar class for your IOS application. The important is, that at some point, your both iOS and watchOS applications has to call `SessionManager.shared.activateSession()` to make transfers possible. Once you activate your session on the device, you can use all APIs related to the communication.


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
        let config = PowerAuthConfiguration()
        config.instanceId = "your-ios-app-bundle-name";
        config.appKey = "sbG8gd...MTIzNA=="
        config.appSecret = "aGVsbG...MTIzNA=="
        config.masterServerPublicKey = "MTIzNDU2Nz...jc4OTAxMg=="
        // URL is optional, current version of Watch SDK doesn't perform own networking.
        config.baseEndpointUrl = "https://localhost:8080/demo-server"

        return PowerAuthWatchSDK(configuration: config)!
    }

    ... the rest of the controller's code ...
}
```

**IMPORTANT**: The configuration used above must match configuration used in the IOS application otherwise `PowerAuthWatchSDK` instance will never be synchronized with its iOS counterpart. Take a special care of `instanceId` property, which **has to match with value from iPhone**. By default, PowerAuth for iOS is using application's bundle-id, so don't make a mistake and don't use watchOS application's bundle identifier.

The Watch SDK doesn't provide a shared instance for `PowerAuthWatchSDK` class and therefore you have to manage that instance on your own. The example above shows a beginning of controller implementing simple WatchKit scene. For all other code examples, we're going to use `self.powerAuthWatch` as properly initialized instance of `PowerAuthWatchSDK` object.


## Getting Device Activation Status

Unlike the iOS SDK, the Watch SDK provides only a limited information about activation status. You can actually check only whether there's locally stored activation on iPhone, or not:

```swift
if self.powerAuthWatch.hasValidActivation() {
    // main application has a valid activation locally stored
}
```

The `hasValidActivation()` method is synchronous and reflects only actual state stored locally on Apple Watch. To get update from iPhone, you can use following code:

```swift
// Lazy version

if !self.powerAuthWatch.updateActivationStatus() {
    // message has not been issued, WCSession is probably not available / active
} else {
    // message has been issued and it's guaranteed that it will be delivered to iPhone
    // The iPhone has to issue response in similar lazy way.
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

The asynchronous `updateActivationStatus` method can be used only if `WCSession` reports that counterpart device is reachable.



## Token Based Authentication

WARNING: Before you start using access tokens, please visit our [wiki page for powerauth-crypto](https://github.com/wultra/powerauth-crypto/blob/develop/docs/MAC-Token-Based-Authentication.md) for more information about this feature. You can also check documentation about tokens available in [PowerAuth SDK for iOS](./PowerAuth-SDK-for-iOS.md#token-based-authentication).

The basic principles for working with tokens on watchOS are the same as for iOS applications, so the interface is practically identical to what you know from PowerAuth SDK for iOS. The main difference is that watchOS application cannot ask PowerAuth server to create a new token, but as a replacement, it can ask for token already stored on the iPhone. In fact, from point of watchOS application's view, the iOS application is just a kind of "remote server" providing tokens.


### Getting token

To get an access token already stored on watch device, you can use following code:

```swift
if let token = self.powerAuthWatch.tokenStore.localToken(withName: "MyToken") {
    // you have a token which can generate authorization headers
}
```

### Getting token from iPhone

To get an access token already stored on iPhone, you can use following code:

```swift
self.powerAuthWatch.tokenStore.requestAccessToken(withName: "MyToken") { (token, error) in
    if let token = token {
        // the access token is valid
    } else {
        // an error occurred
    }
}
```

### Generating authorization header

Once you have a `PowerAuthToken` object, use following code to generate an authorization header:

```swift
if let header = token.generateHeader() {
    let httpHeader = [ header.key : header.value ]
    // now you can attach that httpHeader to your HTTP request
} else {
    // in case of nil, token is no longer valid
}
```

### Removing token locally

To remove token locally, you can simply use following code:

```swift
let tokenStore = self.powerAuthWatch.tokenStore
// Remove just one token
tokenStore.removeLocalToken(withName: "MyToken")
// Remove all local tokens
tokenStore.removeAllLocalTokens()
```

Note that removing tokens locally on watch device has no effect on the same tokens stored on iPhone.

### Removing token from iPhone

The token store available on watchOS exposes `removeAccessToken()` method, but the implementation always returns `PA2ErrorCodeInvalidToken` error. This kind of operation is not supported.



## Common SDK Tasks

### Error Handling

You can follow the same practices as for iOS SDK because Watch SDK codebase is sharing the same error constants with a full PowerAuth SDK for iOS.


### Debug build detection

It is sometimes useful to switch Watch SDK to a DEBUG build configuration, to get more logs from the library:

- **CocoaPods:** we currently don't provide DEBUG pod. This will be resolved in some future versions of Watch SDK.
- **Manual installation:** Xcode is matching build configuration across all nested projects, so you usually don't need to care about the configuration switching.

The DEBUG build is usually helpful during the application development, but on other side, it's highly unwanted in production applications. For this purpose, the `PA2ExtensionLibrary.isInDebug()` method provides an information, whether the PowerAuth for watchOS library was compiled in DEBUG configuration. It is a good practice to check this flag and crash the process when the production application is linked against the DEBUG library:

```swift
#if YOUR_APPSTORE_BUILD_FLAG
    // Final vs Debug library trap
    if PA2ExtensionLibrary.isInDebug() {
        fatalError("CRITICAL ERROR: You're using Debug PowerAuth library in production build.")
    }
#endif
```



## Troubleshooting

This section of document contains a various workarounds and tips for Watch SDK usage.

### WCSession activation sequence on iOS

You should check recommendations about [WCSession's activation sequence on IOS](./PowerAuth-SDK-for-iOS.md#wcsession-activation-sequence).

### Cocoapods integration fails

In case that `pod update` fails on various errors, try following workarounds:

- Update your pod tool at first:
  ```bash
  $ echo before `pod --version`
  $ sudo gem install cocoapods
  $ echo after  `pod --version`
  ```

- To reveal more details about the problem, try to run update with a verbose switch:
  ```bash
   $ pod update --verbose
  ```

- Clean your pod cache. You can remove one specific pod from cache, or clean it all:
  ```bash
  $ pod cache clean PowerAuth2
  $ pod cache clean PowerAuth2ForWatch
  $ pod cache clean PowerAuth2ForExtensions
  $ pod cache clean --all
  ```

- Try to run `pod update` for twice. The cocoapods tool is mystery and sometimes just doesn't work as you would expect.
