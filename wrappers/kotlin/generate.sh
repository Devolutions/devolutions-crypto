#!/bin/sh
# please run setup.sh to setup all required tools

rm -rf bindings
rm -rf output
rm -rf jniLibs

LIBNAME="uniffi_lib"
LIBNAMEBUILD="uniffi-lib"

rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add i686-linux-android
rustup target add x86_64-linux-android

cargo build -p "$LIBNAMEBUILD"

cargo run -p uniffi-bindgen generate --library "../../target/debug/lib$LIBNAME.so"  --language kotlin -o bindings --no-format

cargo build --release --target=aarch64-linux-android -p "$LIBNAMEBUILD"
cargo build --release --target=armv7-linux-androideabi -p "$LIBNAMEBUILD"
cargo build --release --target=i686-linux-android -p "$LIBNAMEBUILD"
cargo build --release --target=x86_64-linux-android -p "$LIBNAMEBUILD"


mkdir jniLibs

mkdir -p jniLibs/arm64-v8a/
cp "../../target/aarch64-linux-android/release/lib$LIBNAME.so" "jniLibs/arm64-v8a/lib$LIBNAME.so"
mkdir -p jniLibs/armeabi-v7a/
cp "../../target/armv7-linux-androideabi/release/lib$LIBNAME.so" "jniLibs/armeabi-v7a/lib$LIBNAME.so"
mkdir -p jniLibs/x86/
cp "../../target/i686-linux-android/release/lib$LIBNAME.so" "jniLibs/x86/lib$LIBNAME.so"
mkdir -p jniLibs/x86_64/
cp "../../target/x86_64-linux-android/release/lib$LIBNAME.so" "jniLibs/x86_64/lib$LIBNAME.so"

