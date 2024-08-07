rm -rf bindings
rm -rf output

cargo run -p uniffi-bindgen generate --library "../../target/debug/libuniffi_lib.dylib"  --language swift -o bindings --no-format

mkdir ./bindings/mac
mkdir ./bindings/ios-simulator

rustup target add x86_64-apple-ios # iOS Simulator on Intel based mac
rustup target add aarch64-apple-ios-sim # iOS Simulator on Arm based mac
rustup target add aarch64-apple-ios # iOS & iPad
rustup target add aarch64-apple-darwin # Arm based mac
rustup target add x86_64-apple-darwin # Intel based mac


cargo build --release --target=x86_64-apple-ios -p uniffi-lib
cargo build --release --target=aarch64-apple-ios-sim -p uniffi-lib
cargo build --release --target=aarch64-apple-ios -p uniffi-lib
cargo build --release --target=aarch64-apple-darwin -p uniffi-lib
cargo build --release --target=x86_64-apple-darwin -p uniffi-lib


mv ./bindings/uniffi_libFFI.modulemap ./bindings/module.modulemap
 
# combine the platforms 

# ios simulator
lipo ../../target/x86_64-apple-ios/release/libuniffi_lib.a \
    ../../target/aarch64-apple-ios-sim/release/libuniffi_lib.a \
    -create -output ./bindings/ios-simulator/libuniffi_lib.a

# mac
lipo ../../target/x86_64-apple-darwin/release/libuniffi_lib.a \
    ../../target/aarch64-apple-darwin/release/libuniffi_lib.a \
    -create -output ./bindings/mac/libuniffi_lib.a


# no need to combine ios

# create the XCFramework
xcodebuild -create-xcframework \
            -library ./bindings/ios-simulator/libuniffi_lib.a -headers ./bindings \
            -library ./bindings/mac/libuniffi_lib.a -headers ./bindings \
            -library ../../target/aarch64-apple-ios/release/libuniffi_lib.a -headers ./bindings \
            -output "./output/devolutions-crypto.xcframework"





