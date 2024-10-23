ROOT = ../..

LIB_NAME = devolutions_crypto_uniffi
LIB_NAME_DASHES = devolutions-crypto-uniffi

DEBUG_DIR = $(ROOT)/target/debug
DEBUG_DLL = $(DEBUG_DIR)/lib$(LIB_NAME).so

KOTLIN_WRAPPER = ./lib/src/main/kotlin
KOTLIN_WRAPPER_FILE = $(KOTLIN_WRAPPER)/org/devolutions/crypto/devolutions_crypto.kt

UNIFFI_PATH = $(ROOT)/uniffi
UNIFFI_BINDGEN = $(UNIFFI_PATH)/uniffi-bindgen
DC_UNIFFI = $(UNIFFI_PATH)/$(LIB_NAME_DASHES)
DC_UNIFFI_SOURCES = $(wildcard $(ROOT)/src/*) $(ROOT)/Cargo.toml $(wildcard $(DC_UNIFFI)/src/*) $(DC_UNIFFI)/Cargo.toml
UNIFFI_BINDGEN_EXE = $(DEBUG_DIR)/uniffi-bindgen

RUST_ARCHS = aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
ANDROID_ARCHS = android-arm64-v8a android-armeabi-v7a android-x86 android-x86-64

KT_DEBUG_PATH = ./lib/src/main/resources/linux-x86-64/lib$(LIB_NAME).so
KT_RELEASE_PATH = $(foreach var,$(ANDROID_ARCHS),./lib/src/main/resources/$(var)/lib$(LIB_NAME).so)

.PHONY: android clean

all: $(KOTLIN_WRAPPER_FILE) $(KT_DEBUG_PATH)

android: $(KOTLIN_WRAPPER_FILE) $(KT_RELEASE_PATH)

# Build the library in debug
$(DEBUG_DLL): $(DC_UNIFFI_SOURCES)
	cargo build -p "$(LIB_NAME_DASHES)"

# Build the release android libraries
$(ROOT)/target/%/release/lib$(LIB_NAME).so: $(DC_UNIFFI_SOURCES)
	cargo build --release --target=$* -p "$(LIB_NAME_DASHES)"

# Copy the libraries to KT directory
# TODO: Can we loop this?
$(KT_DEBUG_PATH): $(DEBUG_DLL)
	mkdir -p $(@D)
	cp $< $@

./lib/src/main/resources/android-arm64-v8a/lib$(LIB_NAME).so: $(ROOT)/target/aarch64-linux-android/release/lib$(LIB_NAME).so
	mkdir -p $(@D)
	cp $< $@

./lib/src/main/resources/android-armeabi-v7a/lib$(LIB_NAME).so: $(ROOT)/target/armv7-linux-androideabi/release/lib$(LIB_NAME).so
	mkdir -p $(@D)
	cp $< $@

./lib/src/main/resources/android-x86/lib$(LIB_NAME).so: $(ROOT)/target/i686-linux-android/release/lib$(LIB_NAME).so
	mkdir -p $(@D)
	cp $< $@

./lib/src/main/resources/android-x86-64/lib$(LIB_NAME).so: $(ROOT)/target/x86_64-linux-android/release/lib$(LIB_NAME).so
	mkdir -p $(@D)
	cp $< $@

# Build uniffi-bindgen
$(UNIFFI_BINDGEN_EXE): $(wildcard $(UNIFFI_BINDGEN)/src/*) $(UNIFFI_BINDGEN)/Cargo.toml
	cargo build -p "uniffi-bindgen"

# Generate the wrapper file
$(KOTLIN_WRAPPER_FILE): $(DEBUG_DLL) $(UNIFFI_BINDGEN_EXE)
	$(UNIFFI_BINDGEN_EXE) generate --library "$(DEBUG_DLL)" --language kotlin -o $(KOTLIN_WRAPPER)

clean:
	cargo clean
	rm $(KOTLIN_WRAPPER_FILE)
	rm $(KT_RELEASE_PATH)
