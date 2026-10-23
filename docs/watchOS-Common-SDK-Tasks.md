# Common SDK Tasks

## Error Handling

You can follow the same practices as for iOS SDK because the Watch SDK codebase shares the same error constants with a full PowerAuth SDK for iOS.

## Debug Build Detection

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

## Read Next

- [Troubleshooting](watchOS-Troubleshooting.md)
