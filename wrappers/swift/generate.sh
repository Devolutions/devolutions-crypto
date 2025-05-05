#!/bin/sh
# based on https://rhonabwy.com/2023/02/10/creating-an-xcframework


XCFRAMEWORK_FOLDER="./output/libDevolutionsCrypto.xcframework"
LIBNAME="DevolutionsCrypto"
LIBNAMEBUILD="devolutions-crypto-uniffi"
LIBNAMEOUTPUT="devolutions_crypto_uniffi"

rm -rf ./bindings
rm -rf ./output

cargo build -p "$LIBNAMEBUILD"

cargo run -p uniffi-bindgen generate --library "../../target/debug/lib$LIBNAMEOUTPUT.dylib"  --language swift -o bindings --no-format

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
 
# combine the platforms 

# ios simulator
lipo "../../target/x86_64-apple-ios/release/lib$LIBNAMEOUTPUT.dylib" \
    "../../target/aarch64-apple-ios-sim/release/lib$LIBNAMEOUTPUT.dylib" \
    -create -output "./bindings/ios-simulator/lib$LIBNAME.dylib"

# mac
lipo ../../target/x86_64-apple-darwin/release/lib$LIBNAMEOUTPUT.dylib \
    ../../target/aarch64-apple-darwin/release/lib$LIBNAMEOUTPUT.dylib \
    -create -output ./bindings/mac/lib$LIBNAME.dylib

# no need to combine ios

# create frameworks
mkdir -p ./framework-simulator/lib$LIBNAME.framework
mkdir -p ./framework-ios/lib$LIBNAME.framework
mkdir -p ./framework-macos/lib$LIBNAME.framework

mkdir ./framework-simulator/lib$LIBNAME.framework/Headers
mkdir ./framework-ios/lib$LIBNAME.framework/Headers
mkdir ./framework-macos/lib$LIBNAME.framework/Headers

cp ./bindings/devolutions_cryptoFFI.h ./framework-simulator/lib$LIBNAME.framework/Headers
cp ./bindings/devolutions_cryptoFFI.h ./framework-ios/lib$LIBNAME.framework/Headers
cp ./bindings/devolutions_cryptoFFI.h ./framework-macos/lib$LIBNAME.framework/Headers
cp ./bindings/devolutions_cryptoFFI.h ./DevolutionsCryptoSwift/Sources/devolutions_cryptoFFI/

mkdir ./framework-simulator/lib$LIBNAME.framework/Modules
mkdir ./framework-ios/lib$LIBNAME.framework/Modules
mkdir ./framework-macos/lib$LIBNAME.framework/Modules

cp ./DevolutionsCryptoSwift/Sources/devolutions_cryptoFFI/framework.modulemap ./framework-simulator/lib$LIBNAME.framework/Modules/module.modulemap
cp ./DevolutionsCryptoSwift/Sources/devolutions_cryptoFFI/framework.modulemap ./framework-ios/lib$LIBNAME.framework/Modules/module.modulemap
cp ./DevolutionsCryptoSwift/Sources/devolutions_cryptoFFI/framework.modulemap ./framework-macos/lib$LIBNAME.framework/Modules/module.modulemap

mkdir ./framework-simulator/lib$LIBNAME.framework/Sources
mkdir ./framework-ios/lib$LIBNAME.framework/Sources
mkdir ./framework-macos/lib$LIBNAME.framework/Sources

cp ./bindings/devolutions_crypto.swift ./framework-simulator/lib$LIBNAME.framework/Sources
cp ./bindings/devolutions_crypto.swift ./framework-ios/lib$LIBNAME.framework/Sources
cp ./bindings/devolutions_crypto.swift ./framework-macos/lib$LIBNAME.framework/Sources

mv "./bindings/ios-simulator/lib$LIBNAME.dylib" ./framework-simulator/lib$LIBNAME.framework/lib$LIBNAME
mv "../../target/aarch64-apple-ios/release/lib$LIBNAMEOUTPUT.dylib" ./framework-ios/lib$LIBNAME.framework/lib$LIBNAME
mv "./bindings/mac/lib$LIBNAME.dylib" ./framework-macos/lib$LIBNAME.framework/lib$LIBNAME

# Fixing rpath
echo "Fixing rpath"
install_name_tool -id "@rpath/lib$LIBNAME.framework/lib$LIBNAME" "./framework-ios/lib$LIBNAME.framework/lib$LIBNAME"
install_name_tool -id "@rpath/lib$LIBNAME.framework/lib$LIBNAME" "./framework-simulator/lib$LIBNAME.framework/lib$LIBNAME"
install_name_tool -id "@rpath/lib$LIBNAME.framework/lib$LIBNAME" "./framework-macos/lib$LIBNAME.framework/lib$LIBNAME"

# frameworks plist
VERSION=$(grep 'version'  ../csharp/config.txt | cut -d '=' -f2 | tr -d ' "')
NOW=$(date +"%H%M")
FULL_VERSION="${VERSION}.${NOW}"
sed -i "" -e "s/||VERSION||/${FULL_VERSION}/g" -e "s/||SHORT_VERSION||/${VERSION}/g" ../csharp/nuget/iOS/Info.plist
sed -i "" -e "s/||VERSION||/${FULL_VERSION}/g" -e "s/||SHORT_VERSION||/${VERSION}/g" ./macos/Info.plist

cp ../csharp/nuget/iOS/Info.plist ./framework-simulator/lib$LIBNAME.framework/
cp ../csharp/nuget/iOS/Info.plist ./framework-ios/lib$LIBNAME.framework/
cp ./macos/Info.plist ./framework-macos/lib$LIBNAME.framework/

# create the XCFramework
xcodebuild -create-xcframework \
            -framework ./framework-simulator/lib$LIBNAME.framework \
            -framework ./framework-ios/lib$LIBNAME.framework \
            -framework ./framework-macos/lib$LIBNAME.framework \
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

cp -R $XCFRAMEWORK_FOLDER ./package
cp -R ./DevolutionsCryptoSwift/Sources ./package
cp -R ./DevolutionsCryptoSwift/Tests ./package
rm ./package/Sources/devolutions_cryptoFFI/framework.modulemap
cp ./DevolutionsCryptoSwift/Package.swift ./package
cp ./DevolutionsCryptoSwift.podspec ./package

sed -i '' 's|\.\./output/libDevolutionsCrypto\.xcframework|./libDevolutionsCrypto\.xcframework|g' ./package/Package.swift


