# Installation

<!-- SIDEBAR _Sidebar.md -->
<!-- BREADCRUMB watchOS href=../PowerAuth-SDK-for-watchOS -->

This chapter describes how to get PowerAuth SDK for watchOS up and running in your app. In the current version, you can choose between Swift Package Manager and CocoaPods library integration.

To distinguish between SDKs, the following short terms will be used in this document:

- **iOS SDK**, as short term for *PowerAuth SDK for iOS*
- **Watch SDK** as short term for *PowerAuth SDK for watchOS*

## Swift Package Manager

Add `https://github.com/wultra/powerauth-mobile-watch-sdk` repository as a package in Xcode UI and add the `PowerAuth2ForWatch` library as a dependency.

Alternatively, you can add the dependency manually. For example:

```swift
// swift-tools-version:6.3
import PackageDescription
let package = Package(
    name: "YourLibrary",
    platforms: [
        .watchOS(.v9)
    ],
    products: [
        .library(
            name: "YourLibrary",
            targets: ["YourLibrary"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/wultra/powerauth-mobile-watch-sdk", from: "2.1.0")
    ],
    targets: [
        .target(
            name: "YourLibrary",
            dependencies: [
                .product(name: "PowerAuth2ForWatch", package: "powerauth-mobile-watch-sdk")
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
target 'YourAppTarget' do
  platform :ios, '15.0'
  pod 'PowerAuth2'
end

target 'YourWatchAppTarget' do
  platform :watchos, '9.0'
  pod 'PowerAuth2ForWatch'
end
```

Then, run the following command:

```bash
$ pod install
```

<!-- begin box info -->
Check [troubleshooting section](Troubleshooting.md#cocoapods-integration-fails) of this document when `pod update` or `pod install` doesn't work.
<!-- end -->

## Read Next

- [SDK Configuration](Configuration.md)
