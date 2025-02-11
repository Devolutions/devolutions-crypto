# Setup a wsl ubuntu 24.04 to compile devolutions crypto kotlin
sudo apt update
sudo apt install unzip openjdk-17-jdk-headless make gcc-multilib software-properties-common -y
sudo apt install gcc-aarch64-linux-gnu -y

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

. "$HOME/.cargo/env"

cargo --version

EXPORT_LINE='export PATH="$HOME/.cargo/bin:$PATH"'
echo "$EXPORT_LINE" >> "$HOME/.bashrc"

rustup target add x86_64-unknown-linux-gnu
rustup target add i686-unknown-linux-gnu
rustup target add aarch64-unknown-linux-gnu

rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add i686-linux-android
rustup target add x86_64-linux-android

sudo rm -rf /usr/local/lib/android
sudo mkdir -p /usr/local/lib/android/sdk

ANDROID_ROOT="/usr/local/lib/android"
ANDROID_SDK_ROOT="${ANDROID_ROOT}/sdk"

EXPORT_LINE='export ANDROID_ROOT="/usr/local/lib/android"'
echo "$EXPORT_LINE" >> "$HOME/.bashrc"
EXPORT_LINE='export ANDROID_SDK_ROOT="${ANDROID_ROOT}/sdk"'
echo "$EXPORT_LINE" >> "$HOME/.bashrc"


cd /usr/local/lib/android/sdk
sudo wget https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
sudo unzip commandlinetools-linux-11076708_latest.zip 
 
sudo cp -r "${ANDROID_SDK_ROOT}/cmdline-tools/." "${ANDROID_SDK_ROOT}/cmdline-tools/latest/"


SDKMANAGER="${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager"
echo "y" | sudo $SDKMANAGER "ndk;27.2.12479018" "build-tools;35.0.0" "platforms;android-34" "platform-tools"

export ANDROID_NDK=$ANDROID_SDK_ROOT/ndk-bundle
EXPORT_LINE='export ANDROID_NDK="$ANDROID_SDK_ROOT/ndk-bundle"'
echo "$EXPORT_LINE" >> "$HOME/.bashrc"

rm /home/$USER/.cargo/config

echo "[target.aarch64-linux-android]
        ar = \"$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar\"
        linker = \"$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang\"
        [target.armv7-linux-androideabi]
        ar = \"$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar\"
        linker = \"$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi21-clang\"
        [target.i686-linux-android]
        ar = \"$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar\"
        linker = \"$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android21-clang\"
        [target.x86_64-linux-android]
        ar = \"$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar\"
        linker = \"$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android21-clang\"" >> "/home/$USER/.cargo/config"

sudo ln -sfn $ANDROID_SDK_ROOT/ndk/27.2.12479018 $ANDROID_NDK

# install kotlin
sudo snap install --classic kotlin

# install ktlint
sudo snap install ktlint --edge --devmode

# Set environment variables for blake3 custom build script
export CC_aarch64_linux_android="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang"
export AR_aarch64_linux_android="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
export CC_armv7_linux_androideabi="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi21-clang"
export AR_armv7_linux_androideabi="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
export CC_i686_linux_android="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android21-clang"
export AR_i686_linux_android="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
export CC_x86_64_linux_android="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android21-clang"
export AR_x86_64_linux_android="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"

ENV_VARS=$(cat << 'EOF'
# Set environment variables for blake3 custom build script
export CC_aarch64_linux_android="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang"
export AR_aarch64_linux_android="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
export CC_armv7_linux_androideabi="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi21-clang"
export AR_armv7_linux_androideabi="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
export CC_i686_linux_android="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android21-clang"
export AR_i686_linux_android="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
export CC_x86_64_linux_android="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android21-clang"
export AR_x86_64_linux_android="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
EOF
)

echo "$ENV_VARS" >> "$HOME/.bashrc"