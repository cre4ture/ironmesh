// swift-tools-version: 6.1

import PackageDescription

let package = Package(
    name: "AppleFileProvider",
    defaultLocalization: "en",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(name: "AppleCore", targets: ["AppleCore"]),
        .library(name: "AppleFileProviderShared", targets: ["AppleFileProviderShared"]),
    ],
    targets: [
        .target(
            name: "AppleCore",
            dependencies: [],
            path: "Sources/AppleCore"
        ),
        .target(
            name: "AppleFileProviderShared",
            dependencies: ["AppleCore"],
            path: "Sources/AppleFileProviderShared"
        ),
        .testTarget(
            name: "AppleCoreTests",
            dependencies: ["AppleCore"],
            path: "Tests/AppleCoreTests"
        ),
        .testTarget(
            name: "AppleFileProviderSharedTests",
            dependencies: ["AppleFileProviderShared"],
            path: "Tests/AppleFileProviderSharedTests"
        ),
    ]
)
