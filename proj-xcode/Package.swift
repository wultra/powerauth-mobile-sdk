// swift-tools-version: 6.3
import PackageDescription

let package = Package(
    name: "PowerAuthCore",
    platforms: [
        .iOS(.v13),
        .tvOS(.v13),
        .macCatalyst(.v13)
    ],
    products: [
        .library(name: "PowerAuthCore", type: .dynamic, targets: ["PowerAuthCore"])
    ],
    dependencies: [
        .package(url: "https://github.com/wultra/cc7", exact: "0.7.0-spm2")
    ],
    targets: [

        // --- PowerAuthCore ---
        
        .target(
            name: "PowerAuthCore",
            dependencies: [
                "PowerAuthCpp"
            ],
            path: ".",
            exclude: [
                "PowerAuthCore/Info.plist",
                "PowerAuthCore/module.modulemap",
                "PowerAuthCore/PowerAuthCorePrivateImpl.h"
            ],
            sources: [
                "PowerAuthCore"
            ],
            publicHeadersPath: "PowerAuthCore",
            cSettings: [
                // Required for <PowerAuthCore/Header.h> style imports.
                .headerSearchPath("."),
                // Required for "Header.h" style imports
                .headerSearchPath("PowerAuthCore")
            ]
        ),
                
        // --- PowerAuthCpp ---
        
        .target(
            name: "PowerAuthCpp",
            dependencies: [
                .product(name: "cc7", package: "cc7")
            ],
            path: "..",
            exclude: [
                "include/PowerAuthTests",
            ],
            sources: [
                "src/PowerAuth"
            ],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("include")
            ]
        ),
                        
        // --- PowerAuthCoreTests ---
        
        .testTarget(
            name: "PowerAuthCoreTests",
            dependencies: [
                "PowerAuthCore",
                "PowerAuthCppTests"
            ],
            path: ".",
            exclude: [
                "PowerAuthCoreTests/Info.plist"
            ],
            sources: [
                "PowerAuthCoreTests"
            ],
            cSettings: [
                // Required for <PowerAuthCore/Header.h> style imports.
                .headerSearchPath("."),
                // Required for "Header.h" style imports
                .headerSearchPath("PowerAuthCoreTests")
            ]
        ),
        
        // --- PowerAuthCppTests ---
        
        .target(
            name: "PowerAuthCppTests",
            dependencies: [
                "PowerAuthCpp",
                .product(name: "cc7tests", package: "cc7"),
            ],
            path: "..",
            exclude: [
                "include/PowerAuth",
                "src/PowerAuthTests/TestData/pa2.conf",
                "src/PowerAuthTests/TestData/pa2",
                "src/PowerAuthTests/TestData/update-pa2-files.sh"
            ],
            sources: [
                "src/PowerAuthTests"
            ],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("include")
            ]
        ),

    ],
    cLanguageStandard: .c17,
    cxxLanguageStandard: .cxx20
)
