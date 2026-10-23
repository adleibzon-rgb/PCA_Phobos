// swift-tools-version:5.5
// Vendored WireGuardKit (github.com/WireGuard/wireguard-apple, MIT). libwg-go.a is
// prebuilt in ../WireGuardGo/<sdk>/ — the app target adds it to LIBRARY_SEARCH_PATHS.
import PackageDescription

let package = Package(
    name: "WireGuardKit",
    platforms: [.iOS(.v15)],
    products: [.library(name: "WireGuardKit", targets: ["WireGuardKit"])],
    targets: [
        .target(name: "WireGuardKit", dependencies: ["WireGuardKitGo", "WireGuardKitC"]),
        .target(name: "WireGuardKitC", publicHeadersPath: "."),
        .target(name: "WireGuardKitGo", publicHeadersPath: ".", linkerSettings: [.linkedLibrary("wg-go")]),
    ]
)
