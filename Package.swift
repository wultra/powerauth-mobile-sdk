// swift-tools-version: 6.3
import PackageDescription

let package = Package(
    name: "PowerAuth",
    platforms: [
        .iOS(.v13),
        .tvOS(.v13),
        .macCatalyst(.v13)
    ],
    products: [
        .library(name: "PowerAuth2", type: .dynamic, targets: ["PowerAuth2"])
    ],
    dependencies: [
        .package(url: "https://github.com/wultra/cc7", exact: "0.7.0-spm3")
    ],
    targets: [
        
        // --- PowerAuth2 ---
        
        .target(
            name: "PowerAuth2",
            dependencies: [
                "PowerAuthCore"
            ],
            path: "proj-xcode",
            exclude: [
                "PowerAuth2/Info.plist",
                "PowerAuth2/module.modulemap",
            ],
            sources: [
                "PowerAuth2",
                "PowerAuth2Private",
            ],
            publicHeadersPath: "PowerAuth2",
            cSettings: [
                // Required for <PowerAuth2/Header.h> style imports.
                .headerSearchPath("."),
                // Required for "Header.h" style imports
                .headerSearchPath("PowerAuth2"),
                .headerSearchPath("PowerAuth2Private"),
            ]
        ),
                
        // --- PowerAuth2Tests ---
        
        .testTarget(
            name: "PowerAuth2Tests",
            dependencies: [
                "PowerAuth2",
                "PowerAuth2TestsBase"
            ],
            path: "proj-xcode",
            exclude: [
                "PowerAuth2Tests/Info.plist"
            ],
            sources: [
                "PowerAuth2Tests"
            ],
            cSettings: [
                // Required for <PowerAuth2/Header.h> style imports.
                .headerSearchPath("."),
                // Required for "Header.h" style imports
                .headerSearchPath("PowerAuth2Tests"),
                // Custom imports
                .headerSearchPath("PowerAuth2Private"),
                //.headerSearchPath("PowerAuth2TestsBase")
            ]
        ),
        
        // --- PowerAuthCoreTests ---
        
        .testTarget(
            name: "PowerAuthCoreTests",
            dependencies: [
                "PowerAuthCore",
                "PowerAuthCppTests"
            ],
            path: "proj-xcode",
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
        
        // --- PowerAuth2TestsBase ---
        
        .target(
            name: "PowerAuth2TestsBase",
            dependencies: [
                "PowerAuthCore",
                "PowerAuth2"
            ],
            path: "proj-xcode",
            sources: [
                "PowerAuth2TestsBase"
            ],
            publicHeadersPath: "PowerAuth2TestsBase",
            cSettings: [
                .headerSearchPath("."),
                .headerSearchPath("PowerAuth2TestsBase"),
                .headerSearchPath("PowerAuth2Private")
            ]
        ),
        
        // --- PowerAuthCore ---
        
        .target(
            name: "PowerAuthCore",
            dependencies: [
                "PowerAuthCpp"
            ],
            path: "proj-xcode",
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
            path: ".",
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
        
        // --- PowerAuthCppTests ---
        
        .target(
            name: "PowerAuthCppTests",
            dependencies: [
                "PowerAuthCpp",
                .product(name: "cc7tests", package: "cc7"),
            ],
            path: ".",
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
        )
    ],
    cLanguageStandard: .c17,
    cxxLanguageStandard: .cxx20
)
