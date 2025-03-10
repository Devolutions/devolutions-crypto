#!/bin/sh
# based on https://rhonabwy.com/2023/02/10/creating-an-xcframework


XCFRAMEWORK_FOLDER="./output/DevolutionsCrypto.xcframework"
LIBNAME="devolutions_crypto_uniffi"
LIBNAMEBUILD="devolutions-crypto-uniffi"

rm -rf ./bindings
rm -rf ./output

cargo build -p "$LIBNAMEBUILD"

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


mv "./bindings/devolutions_cryptoFFI.modulemap" ./bindings/module.modulemap
 
# combine the platforms 

# ios simulator
lipo "../../target/x86_64-apple-ios/release/lib$LIBNAME.dylib" \
    "../../target/aarch64-apple-ios-sim/release/lib$LIBNAME.dylib" \
    -create -output "./bindings/ios-simulator/lib$LIBNAME.dylib"

# mac
lipo ../../target/x86_64-apple-darwin/release/lib$LIBNAME.dylib \
    ../../target/aarch64-apple-darwin/release/lib$LIBNAME.dylib \
    -create -output ./bindings/mac/lib$LIBNAME.dylib


# no need to combine ios

# Move headers
mkdir headers
cp ./bindings/devolutions_crypto.swift ./headers
cp ./bindings/devolutions_cryptoFFI.h ./headers
cp ./bindings/module.modulemap ./headers

# create the XCFramework
xcodebuild -create-xcframework \
            -library "./bindings/ios-simulator/lib$LIBNAME.dylib" -headers ./headers \
            -library "./bindings/mac/lib$LIBNAME.dylib" -headers ./headers \
            -library "../../target/aarch64-apple-ios/release/lib$LIBNAME.dylib" -headers ./headers \
            -output "$XCFRAMEWORK_FOLDER"


# Compress XCFramework
ditto -c -k --sequesterRsrc --keepParent "$XCFRAMEWORK_FOLDER" "$XCFRAMEWORK_FOLDER.zip"

# Compute checksum
swift package compute-checksum "$XCFRAMEWORK_FOLDER.zip"

# Move swift file to package
cp "./bindings/devolutions_crypto.swift" ./DevolutionsCryptoSwift/Sources/DevolutionsCryptoSwift/DevolutionsCryptoSwift.swift

# Tests
cd ./DevolutionsCryptoSwift

swift test

cd ../

mkdir package

cp -R ./output/DevolutionsCrypto.xcframework ./package
cp -R ./DevolutionsCryptoSwift/Sources ./package
cp -R ./DevolutionsCryptoSwift/Tests ./package
cp ./DevolutionsCryptoSwift/Package.swift ./package
cp ./DevolutionsCryptoSwift.podspec ./package

sed -i '' 's|\.\./output/DevolutionsCrypto\.xcframework|./DevolutionsCrypto\.xcframework|g' ./package/Package.swift


