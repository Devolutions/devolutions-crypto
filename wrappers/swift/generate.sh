#!/bin/sh
# based on https://rhonabwy.com/2023/02/10/creating-an-xcframework


XCFRAMEWORK_FOLDER="./output/DevolutionsCrypto.xcframework"
LIBNAME="uniffi_lib"
LIBNAMEBUILD="uniffi-lib"

rm -rf bindings
rm -rf output

cargo run -p uniffi-bindgen generate --library "../../target/debug/lib$LIBNAME.dylib"  --language swift -o bindings --no-format

mkdir ./bindings/mac
mkdir ./bindings/ios-simulator

rustup target add x86_64-apple-ios # iOS Simulator on Intel based mac
rustup target add aarch64-apple-ios-sim # iOS Simulator on Arm based mac
rustup target add aarch64-apple-ios # iOS & iPad
rustup target add aarch64-apple-darwin # Arm based mac
rustup target add x86_64-apple-darwin # Intel based mac


cargo build --release --target=x86_64-apple-ios -p "$LIBNAMEBUILD"
cargo build --release --target=aarch64-apple-ios-sim -p "$LIBNAMEBUILD"
cargo build --release --target=aarch64-apple-ios -p "$LIBNAMEBUILD"
cargo build --release --target=aarch64-apple-darwin -p "$LIBNAMEBUILD"
cargo build --release --target=x86_64-apple-darwin -p "$LIBNAMEBUILD"


mv "./bindings/${LIBNAME}FFI.modulemap" ./bindings/module.modulemap
 
# combine the platforms 

# ios simulator
lipo "../../target/x86_64-apple-ios/release/lib$LIBNAME.a" \
    "../../target/aarch64-apple-ios-sim/release/lib$LIBNAME.a" \
    -create -output "./bindings/ios-simulator/lib$LIBNAME.a"

# mac
lipo ../../target/x86_64-apple-darwin/release/lib$LIBNAME.a \
    ../../target/aarch64-apple-darwin/release/lib$LIBNAME.a \
    -create -output ./bindings/mac/lib$LIBNAME.a


# no need to combine ios

# create the XCFramework
xcodebuild -create-xcframework \
            -library "./bindings/ios-simulator/lib$LIBNAME.a" -headers ./bindings \
            -library "./bindings/mac/lib$LIBNAME.a" -headers ./bindings \
            -library "../../target/aarch64-apple-ios/release/lib$LIBNAME.a" -headers ./bindings \
            -output "$XCFRAMEWORK_FOLDER"

# Compress XCFramework
ditto -c -k --sequesterRsrc --keepParent "$XCFRAMEWORK_FOLDER" "$XCFRAMEWORK_FOLDER.zip"

# Compute checksum
swift package compute-checksum "$XCFRAMEWORK_FOLDER.zip"

# Move swift file to package
cp "./bindings/$LIBNAME.swift" ./DevolutionsCryptoSwift/Sources/DevolutionsCryptoSwift/DevolutionsCryptoSwift.swift

# Tests
cd ./DevolutionsCryptoSwift

swift test


