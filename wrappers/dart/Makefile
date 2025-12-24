# Makefile for building Devolutions Crypto Dart bindings

.PHONY: all
all: help

# Platform-specific build targets
.PHONY: windows linux macos android ios bindings

# Generate Dart bindings
bindings:
	@echo "Generating Dart bindings..."
	@chmod +x ./generate.sh
	@./generate.sh

# Build for Windows
windows:
	@echo "Building for Windows x86_64..."
	cargo build --release --target x86_64-pc-windows-gnu -p devolutions-crypto-uniffi
	mkdir -p ./lib/native/windows-x64/
	cp ../../target/x86_64-pc-windows-gnu/release/devolutions_crypto_uniffi.dll ./lib/native/windows-x64/

# Build for Linux
linux:
	@echo "Building for Linux x86_64..."
	cargo build --release --target x86_64-unknown-linux-gnu -p devolutions-crypto-uniffi
	mkdir -p ./lib/native/linux-x64/
	cp ../../target/x86_64-unknown-linux-gnu/release/libdevolutions_crypto_uniffi.so ./lib/native/linux-x64/

# Build for macOS
macos:
	@echo "Building for macOS..."
	cargo build --release --target aarch64-apple-darwin -p devolutions-crypto-uniffi
	cargo build --release --target x86_64-apple-darwin -p devolutions-crypto-uniffi
	mkdir -p ./lib/native/macos-arm64/
	mkdir -p ./lib/native/macos-x64/
	cp ../../target/aarch64-apple-darwin/release/libdevolutions_crypto_uniffi.dylib ./lib/native/macos-arm64/
	cp ../../target/x86_64-apple-darwin/release/libdevolutions_crypto_uniffi.dylib ./lib/native/macos-x64/

# Build for Android
android:
	@echo "Building for Android..."
	cargo build --release --target aarch64-linux-android -p devolutions-crypto-uniffi
	cargo build --release --target armv7-linux-androideabi -p devolutions-crypto-uniffi
	cargo build --release --target i686-linux-android -p devolutions-crypto-uniffi
	cargo build --release --target x86_64-linux-android -p devolutions-crypto-uniffi
	mkdir -p ./lib/native/android-arm64-v8a/
	mkdir -p ./lib/native/android-armeabi-v7a/
	mkdir -p ./lib/native/android-x86/
	mkdir -p ./lib/native/android-x86-64/
	cp ../../target/aarch64-linux-android/release/libdevolutions_crypto_uniffi.so ./lib/native/android-arm64-v8a/
	cp ../../target/armv7-linux-androideabi/release/libdevolutions_crypto_uniffi.so ./lib/native/android-armeabi-v7a/
	cp ../../target/i686-linux-android/release/libdevolutions_crypto_uniffi.so ./lib/native/android-x86/
	cp ../../target/x86_64-linux-android/release/libdevolutions_crypto_uniffi.so ./lib/native/android-x86-64/

# Build for iOS
ios:
	@echo "Building for iOS..."
	rustup target add aarch64-apple-ios
	rustup target add x86_64-apple-ios
	rustup target add aarch64-apple-ios-sim
	cargo build --release --target aarch64-apple-ios -p devolutions-crypto-uniffi
	cargo build --release --target x86_64-apple-ios -p devolutions-crypto-uniffi
	cargo build --release --target aarch64-apple-ios-sim -p devolutions-crypto-uniffi
	mkdir -p ./lib/native/ios-arm64/
	mkdir -p ./lib/native/ios-x64-simulator/
	mkdir -p ./lib/native/ios-arm64-simulator/
	cp ../../target/aarch64-apple-ios/release/libdevolutions_crypto_uniffi.dylib ./lib/native/ios-arm64/
	cp ../../target/x86_64-apple-ios/release/libdevolutions_crypto_uniffi.dylib ./lib/native/ios-x64-simulator/
	cp ../../target/aarch64-apple-ios-sim/release/libdevolutions_crypto_uniffi.dylib ./lib/native/ios-arm64-simulator/

# Build all platforms
all-platforms: windows linux macos android ios

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf ./lib/native/
	rm -rf ./lib/src/generated/
	cargo clean

# Run tests
.PHONY: test
test:
	@echo "Running Dart tests..."
	dart test

# Format code
.PHONY: format
format:
	@echo "Formatting Dart code..."
	dart format lib/ test/ example/

# Analyze code
.PHONY: analyze
analyze:
	@echo "Analyzing Dart code..."
	dart analyze

# Publish to pub.dev (dry run)
.PHONY: publish-dry-run
publish-dry-run:
	@echo "Performing dry run of package publish..."
	dart pub publish --dry-run

# Help target
.PHONY: help
help:
	@echo "Makefile for Devolutions Crypto Dart Bindings"
	@echo ""
	@echo "Usage:"
	@echo "  make bindings          - Generate Dart bindings from Rust"
	@echo "  make windows           - Build for Windows"
	@echo "  make linux             - Build for Linux"
	@echo "  make macos             - Build for macOS"
	@echo "  make android           - Build for Android"
	@echo "  make ios               - Build for iOS"
	@echo "  make all-platforms     - Build for all platforms"
	@echo "  make test              - Run Dart tests"
	@echo "  make format            - Format Dart code"
	@echo "  make analyze           - Analyze Dart code"
	@echo "  make clean             - Clean build artifacts"
	@echo "  make publish-dry-run   - Dry run package publish"
