# Default target
.PHONY: all
all: help

# Platform-specific build targets
.PHONY: android

android:
	cargo build --release --target aarch64-linux-android -p devolutions-crypto-uniffi
	cargo build --release --target armv7-linux-androideabi -p devolutions-crypto-uniffi
	cargo build --release --target i686-linux-android -p devolutions-crypto-uniffi
	cargo build --release --target x86_64-linux-android -p devolutions-crypto-uniffi

	cargo build --release -p uniffi-bindgen
	cargo run --release -p uniffi-bindgen -- generate --library ../../target/aarch64-linux-android/release/libdevolutions_crypto_uniffi.so --language kotlin -o ./lib/src/main/kotlin/

	mkdir -p ./lib/src/main/jniLibs/arm64-v8a/
	mkdir -p ./lib/src/main/jniLibs/armeabi-v7a/
	mkdir -p ./lib/src/main/jniLibs/x86/
	mkdir -p ./lib/src/main/jniLibs/x86_64/

	cp ../../target/aarch64-linux-android/release/libdevolutions_crypto_uniffi.so ./lib/src/main/jniLibs/arm64-v8a/libdevolutions_crypto_uniffi.so 
	cp ../../target/armv7-linux-androideabi/release/libdevolutions_crypto_uniffi.so ./lib/src/main/jniLibs/armeabi-v7a/libdevolutions_crypto_uniffi.so 
	cp ../../target/i686-linux-android/release/libdevolutions_crypto_uniffi.so ./lib/src/main/jniLibs/x86/libdevolutions_crypto_uniffi.so 
	cp ../../target/x86_64-linux-android/release/libdevolutions_crypto_uniffi.so ./lib/src/main/jniLibs/x86_64/libdevolutions_crypto_uniffi.so 


# Clean targets for each platform
.PHONY: clean

clean:
	rm -rf ./lib/src/main/jniLibs/

# Help target
.PHONY: help
help:
	@echo "Makefile Usage:"
	@echo "  make android     - Build for Android"
	@echo "  make clean       - Clean all builds"
