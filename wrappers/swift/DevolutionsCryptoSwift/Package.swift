// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "DevolutionsCryptoSwift",
    platforms: [
        .iOS(.v14),
        .macOS(.v11)
    ],
    products: [
        .library(
            name: "DevolutionsCryptoSwift",
            targets: ["DevolutionsCryptoSwift"]
        )
    ],
    targets: [
        .systemLibrary(
            name: "devolutions_cryptoFFI",
            path: "Sources/devolutions_cryptoFFI"
        ),
        .binaryTarget(
            name: "libDevolutionsCrypto",
            path: "../output/libDevolutionsCrypto.xcframework"
        ),
        .target(
            name: "DevolutionsCryptoSwift",
            dependencies: [
                "devolutions_cryptoFFI",
                "libDevolutionsCrypto"
            ],
            path: "Sources/DevolutionsCryptoSwift"
        ),
        .testTarget(
            name: "DevolutionsCryptoSwiftTests",
            dependencies: [
                "DevolutionsCryptoSwift"
            ],
            path: "Tests/DevolutionsCryptoSwiftTests"
        )
    ]
)