# SDK Installation

<!-- SIDEBAR _Sidebar.md -->

This chapter describes how to get PowerAuth SDK for iOS and tvOS up and running in your app. In the current version, you can choose between Swift Package Manager and CocoaPods library integration.

## Supported Platforms

The library is available for the following Apple platforms:

- **iOS** 15.0+
- **mac Catalyst** 15.0+
- **tvOS** 15.0+

To simplify the documentation, we'll use **iOS** for the rest of the documentation and highlight the exceptions only. For example, **tvOS** doesn't support biometry and watch connectivity.

## Swift Package Manager

Add `https://github.com/wultra/powerauth-mobile-sdk` repository as a package in Xcode UI and add the `PowerAuth2` library as a dependency.

Alternatively, you can add the dependency manually. For example:

```swift
// swift-tools-version:6.3
import PackageDescription
let package = Package(
    name: "YourLibrary",
    platforms: [
        .iOS(.v15)
    ],
    products: [
        .library(
            name: "YourLibrary",
            targets: ["YourLibrary"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/wultra/powerauth-mobile-sdk", from: "2.1.0")
    ],
    targets: [
        .target(
            name: "YourLibrary",
            dependencies: [
                .product(name: "PowerAuth2", package: "powerauth-mobile-sdk")
            ]
        )
    ]
)
```

## CocoaPods

<!-- begin box warning -->
Be aware that CocoaPods will no longer accept updates [by the end of 2026](https://blog.cocoapods.org/CocoaPods-Specs-Repo/). You should migrate your project to Swift Package Manager.
<!-- end -->

[CocoaPods](http://cocoapods.org) is a dependency manager for Cocoa projects. You can install it with the following command:
```bash
$ gem install cocoapods
```

To integrate the PowerAuth library into your Xcode project using CocoaPods, specify it in your `Podfile`:

```ruby
platform :ios, '15.0'
target '<Your Target App>' do
  pod 'PowerAuth2'
end
```

Then, run the following command:

```bash
$ pod install
```

## Read Next

- [SDK Configuration](Configuration.md)
