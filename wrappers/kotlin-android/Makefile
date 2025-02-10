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

	wget https://github.com/java-native-access/jna/raw/refs/heads/master/dist/jna.aar

	unzip -q jna.aar -d extracted_aar

	mkdir -p ./lib/src/main/resources/jni/arm64-v8a/
	mkdir -p ./lib/src/main/resources/jni/armeabi-v7a/
	mkdir -p ./lib/src/main/resources/jni/x86/
	mkdir -p ./lib/src/main/resources/jni/x86_64/

	cp ./extracted_aar/jni/arm64-v8a/libjnidispatch.so ./lib/src/main/resources/jni/arm64-v8a/libjnidispatch.so
	cp ./extracted_aar/jni/armeabi-v7a/libjnidispatch.so ./lib/src/main/resources/jni/armeabi-v7a/libjnidispatch.so
	cp ./extracted_aar/jni/x86/libjnidispatch.so ./lib/src/main/resources/jni/x86/libjnidispatch.so
	cp ./extracted_aar/jni/x86_64/libjnidispatch.so ./lib/src/main/resources/jni/x86_64/libjnidispatch.so

	cp ../../target/aarch64-linux-android/release/libdevolutions_crypto_uniffi.so ./lib/src/main/resources/jni/arm64-v8a/libdevolutions_crypto_uniffi.so 
	cp ../../target/armv7-linux-androideabi/release/libdevolutions_crypto_uniffi.so ./lib/src/main/resources/jni/armeabi-v7a/libdevolutions_crypto_uniffi.so 
	cp ../../target/i686-linux-android/release/libdevolutions_crypto_uniffi.so ./lib/src/main/resources/jni/x86/libdevolutions_crypto_uniffi.so 
	cp ../../target/x86_64-linux-android/release/libdevolutions_crypto_uniffi.so ./lib/src/main/resources/jni/x86_64/libdevolutions_crypto_uniffi.so 


# Clean targets for each platform
.PHONY: clean

clean:
	rm -rf ./lib/src/main/resources/android-aarch64/
	rm -rf ./lib/src/main/resources/android-armv7/
	rm -rf ./lib/src/main/resources/android-x86/
	rm -rf ./lib/src/main/resources/android-x86-64/

	rm -rf ./extracted_aar


# Help target
.PHONY: help
help:
	@echo "Makefile Usage:"
	@echo "  make android     - Build for Android"
	@echo "  make clean       - Clean all builds"
