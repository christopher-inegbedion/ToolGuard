// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "ToolGuard",
    platforms: [.macOS("26.0"), .iOS("26.0")],
    products: [
        .library(name: "ToolGuard", targets: ["ToolGuard"]),
        .library(name: "ToolGuardEval", targets: ["ToolGuardEval"]),
        .executable(name: "toolguard-eval", targets: ["toolguard-eval"]),
    ],
    targets: [
        .target(name: "ToolGuard"),
        .target(name: "ToolGuardEval", dependencies: ["ToolGuard"]),
        .executableTarget(name: "toolguard-eval", dependencies: ["ToolGuardEval", "ToolGuard"]),
        .testTarget(name: "ToolGuardTests", dependencies: ["ToolGuard", "ToolGuardEval"]),
    ]
)
