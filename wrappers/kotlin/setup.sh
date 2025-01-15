# Setup a wsl ubuntu 24.04 to compile devolutions crypto kotlin
sudo apt update
sudo apt install unzip openjdk-17-jre-headless make gcc-multilib software-properties-common -y
sudo apt install gcc-aarch64-linux-gnu -y

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

. "$HOME/.cargo/env"

cargo --version

EXPORT_LINE='export PATH="$HOME/.cargo/bin:$PATH"'
echo "$EXPORT_LINE" >> "$HOME/.bashrc"

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
sudo echo "y" | $SDKMANAGER "ndk;27.2.12479018"

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
