// swift-tools-version:5.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftBSV",
    platforms: [
      .macOS(.v10_12), .iOS(.v9), .tvOS(.v9)
    ],
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "SwiftBSV",
            targets: ["SwiftBSV"]),
    ],
    dependencies: [
        .package(url: "https://github.com/Boilertalk/secp256k1.swift.git", from: "0.1.0"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.0.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "SwiftBSV",
            dependencies: [
                "secp256k1",
                "CryptoSwift"
            ]
        ),
        .testTarget(
            name: "SwiftBSVTests",
            dependencies: ["SwiftBSV"]),
    ]
)
