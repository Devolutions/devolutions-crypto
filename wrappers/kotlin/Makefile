RELEASE ?= 0
ifeq ($(RELEASE), 0)
	BUILD_PROFILE = debug
else
	BUILD_PROFILE = release
	RELEASE_FLAG = --release
endif

ROOT = ../..

LIB_NAME = devolutions_crypto_uniffi
LIB_NAME_DASHES = devolutions-crypto-uniffi

LINUX_DEBUG_DIR = $(ROOT)/target/debug
LINUX_DIR = $(ROOT)/target/$(BUILD_PROFILE)
LINUX_DLL = $(LINUX_DIR)/lib$(LIB_NAME).so

KOTLIN_WRAPPER = ./lib/src/main/kotlin
KOTLIN_WRAPPER_FILE = $(KOTLIN_WRAPPER)/org/devolutions/crypto/devolutions_crypto.kt

UNIFFI_PATH = $(ROOT)/uniffi
UNIFFI_BINDGEN = $(UNIFFI_PATH)/uniffi-bindgen
DC_UNIFFI = $(UNIFFI_PATH)/$(LIB_NAME_DASHES)
DC_UNIFFI_SOURCES = $(wildcard $(ROOT)/src/*) $(ROOT)/Cargo.toml $(wildcard $(DC_UNIFFI)/src/*) $(DC_UNIFFI)/Cargo.toml
UNIFFI_BINDGEN_EXE = $(LINUX_DEBUG_DIR)/uniffi-bindgen

RUST_ARCHS = aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
ANDROID_ARCHS = android-aarch64 android-armv7 android-x86 android-x86-64

KT_LINUX_PATH = ./lib/src/main/resources/linux-x86-64/lib$(LIB_NAME).so
KT_ANDROID_PATH = $(foreach var,$(ANDROID_ARCHS),./lib/src/main/resources/$(var)/lib$(LIB_NAME).so)

.PHONY: all release linux android clean

all: linux

release: linux android

linux: $(KOTLIN_WRAPPER_FILE) $(KT_LINUX_PATH)
android: $(KOTLIN_WRAPPER_FILE) $(KT_ANDROID_PATH)

# Build the library in debug
$(LINUX_DLL): $(DC_UNIFFI_SOURCES)
	cargo build $(RELEASE_FLAG) -p "$(LIB_NAME_DASHES)"

# Copy the libraries to KT directory
$(KT_LINUX_PATH): $(LINUX_DLL)
	mkdir -p $(@D)
	cp $< $@

define compile_android
	cargo build $(RELEASE_FLAG) --target=$(ARCH) -p "$(LIB_NAME_DASHES)"
	mkdir -p $(@D)
	cp $(ROOT)/target/$(ARCH)/$(BUILD_PROFILE)/lib$(LIB_NAME).so $@
endef

./lib/src/main/resources/android-aarch64/lib$(LIB_NAME).so: $(DC_UNIFFI_SOURCES)
	$(eval ARCH=aarch64-linux-android)
	@$(call compile_android)

./lib/src/main/resources/android-armv7/lib$(LIB_NAME).so: $(DC_UNIFFI_SOURCES)
	$(eval ARCH=armv7-linux-androideabi)
	@$(call compile_android)

./lib/src/main/resources/android-x86/lib$(LIB_NAME).so: $(DC_UNIFFI_SOURCES)
	$(eval ARCH=i686-linux-android)
	@$(call compile_android)

./lib/src/main/resources/android-x86-64/lib$(LIB_NAME).so: $(DC_UNIFFI_SOURCES)
	$(eval ARCH=x86_64-linux-android)
	@$(call compile_android)

# Build uniffi-bindgen
$(UNIFFI_BINDGEN_EXE): $(wildcard $(UNIFFI_BINDGEN)/src/*) $(UNIFFI_BINDGEN)/Cargo.toml
	cargo build -p "uniffi-bindgen"

# Generate the wrapper file
$(KOTLIN_WRAPPER_FILE): $(LINUX_DLL) $(UNIFFI_BINDGEN_EXE)
	$(UNIFFI_BINDGEN_EXE) generate --library "$(LINUX_DLL)" --language kotlin -o $(KOTLIN_WRAPPER)

clean:
	cargo clean
	rm -f $(KOTLIN_WRAPPER_FILE)
	rm -f $(KT_ANDROID_PATH)
	rm -f $(KT_LINUX_PATH)
