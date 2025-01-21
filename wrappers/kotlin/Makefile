# Default target
.PHONY: all
all: help

# Platform-specific build targets
.PHONY: windows linux macos android

windows:
	cargo build --release --target x86_64-pc-windows-gnu -p devolutions-crypto-uniffi

	cargo build --release -p uniffi-bindgen
	cargo run --release -p uniffi-bindgen -- generate --library ../../target/x86_64-pc-windows-gnu/release/devolutions_crypto_uniffi.dll --language kotlin -o ./lib/src/main/kotlin/

	mkdir -p ./lib/src/main/resources/win32-x86-64/

	cp ../../target/x86_64-pc-windows-gnu/release/devolutions_crypto_uniffi.dll ./lib/src/main/resources/win32-x86-64/devolutions_crypto_uniffi.dll 

linux:
	cargo build --release --target x86_64-unknown-linux-gnu -p devolutions-crypto-uniffi

	cargo build --release -p uniffi-bindgen
	cargo run --release -p uniffi-bindgen -- generate --library ../../target/x86_64-unknown-linux-gnu/release/libdevolutions_crypto_uniffi.so --language kotlin -o ./lib/src/main/kotlin/
	
	mkdir -p ./lib/src/main/resources/linux-x86-64/

	cp ../../target/x86_64-unknown-linux-gnu/release/libdevolutions_crypto_uniffi.so ./lib/src/main/resources/linux-x86-64/libdevolutions_crypto_uniffi.so 

macos:
	cargo build --release --target aarch64-apple-darwin -p devolutions-crypto-uniffi
	cargo build --release --target x86_64-apple-darwin -p devolutions-crypto-uniffi

	cargo build --release -p uniffi-bindgen
	cargo run --release -p uniffi-bindgen -- generate --library ../../target/aarch64-apple-darwin/release/libdevolutions_crypto_uniffi.dylib --language kotlin -o ./lib/src/main/kotlin/

	mkdir -p ./lib/src/main/resources/darwin-aarch64/
	mkdir -p ./lib/src/main/resources/darwin-x86-64/

	cp ../../target/aarch64-apple-darwin/release/libdevolutions_crypto_uniffi.dylib ./lib/src/main/resources/darwin-aarch64/libdevolutions_crypto_uniffi.dylib
	cp ../../target/x86_64-apple-darwin/release/libdevolutions_crypto_uniffi.dylib ./lib/src/main/resources/darwin-x86-64/libdevolutions_crypto_uniffi.dylib

android:
	cargo build --release --target aarch64-linux-android -p devolutions-crypto-uniffi
	cargo build --release --target armv7-linux-androideabi -p devolutions-crypto-uniffi
	cargo build --release --target i686-linux-android -p devolutions-crypto-uniffi
	cargo build --release --target x86_64-linux-android -p devolutions-crypto-uniffi

	cargo build --release -p uniffi-bindgen
	cargo run --release -p uniffi-bindgen -- generate --library ../../target/aarch64-linux-android/release/libdevolutions_crypto_uniffi.so --language kotlin -o ./lib/src/main/kotlin/

	mkdir -p ./lib/src/main/resources/android-aarch64/
	mkdir -p ./lib/src/main/resources/android-armv7/
	mkdir -p ./lib/src/main/resources/android-x86/
	mkdir -p ./lib/src/main/resources/android-x86-64/

	cp ../../target/aarch64-linux-android/release/libdevolutions_crypto_uniffi.so ./lib/src/main/resources/android-aarch64/libdevolutions_crypto_uniffi.so 
	cp ../../target/armv7-linux-androideabi/release/libdevolutions_crypto_uniffi.so ./lib/src/main/resources/android-armv7/libdevolutions_crypto_uniffi.so 
	cp ../../target/i686-linux-android/release/libdevolutions_crypto_uniffi.so ./lib/src/main/resources/android-x86/libdevolutions_crypto_uniffi.so 
	cp ../../target/x86_64-linux-android/release/libdevolutions_crypto_uniffi.so ./lib/src/main/resources/android-x86-64/libdevolutions_crypto_uniffi.so 


# Clean targets for each platform
.PHONY: clean clean-windows clean-linux clean-macos clean-android

clean: clean-windows clean-linux clean-macos clean-android
	cargo clean
	rm -rf ./lib/src/main/kotlin/org

clean-windows:
	rm -rf ./lib/src/main/resources/win32-x86-64/

clean-linux:
	rm -rf ./lib/src/main/resources/linux-x86-64/

clean-macos:
	rm -rf ./lib/src/main/resources/darwin-aarch64/
	rm -rf ./lib/src/main/resources/darwin-x86-64/

clean-android:
	rm -rf ./lib/src/main/resources/android-aarch64/
	rm -rf ./lib/src/main/resources/android-armv7/
	rm -rf ./lib/src/main/resources/android-x86/
	rm -rf ./lib/src/main/resources/android-x86-64/

# Help target
.PHONY: help
help:
	@echo "Makefile Usage:"
	@echo "  make windows     - Build for Windows"
	@echo "  make linux       - Build for Linux"
	@echo "  make macos       - Build for macOS"
	@echo "  make android     - Build for Android"
	@echo "  make clean       - Clean all builds"
	@echo "  make clean-<platform> - Clean a specific platform build (e.g., clean-windows)"
