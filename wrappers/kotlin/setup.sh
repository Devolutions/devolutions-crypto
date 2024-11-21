# run as root
curl https://sh.rustup.rs -sSf | sh -s -- -y
echo "${HOME}/.cargo/bin" >> "$GITHUB_PATH"
export PATH="${HOME}/.cargo/bin:$PATH"
echo "RUSTUP_HOME=${HOME}/.rustup" >> "$GITHUB_ENV"
echo "CARGO_HOME=${HOME}/.cargo" >> "$GITHUB_ENV"

rustup update

rustup target add x86_64-unknown-linux-gnu
rustup target add i686-unknown-linux-gnu
rustup target add aarch64-unknown-linux-gnu

rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add i686-linux-android
rustup target add x86_64-linux-android

apt install build-essential unzip openjdk-18-jre-headless
apt install nuget gcc-multilib software-properties-common
apt install -y gcc-aarch64-linux-gnu

rm -rf /usr/local/lib/android
mkdir -p /usr/local/lib/android/sdk

ANDROID_ROOT="/usr/local/lib/android"
ANDROID_SDK_ROOT="${ANDROID_ROOT}/sdk"

cd /usr/local/lib/android/sdk
wget https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
unzip commandlinetools-linux-11076708_latest.zip 
 
cp -r "${ANDROID_SDK_ROOT}/cmdline-tools/." "${ANDROID_SDK_ROOT}/cmdline-tools/latest/"


SDKMANAGER="${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager"
echo "y" | $SDKMANAGER "ndk;25.2.9519653"



export ANDROID_NDK=$ANDROID_SDK_ROOT/ndk-bundle


rm /home/$SUDO_USER/.cargo/config

echo "[target.aarch64-linux-android]
        ar = \"$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android-ar\"
        linker = \"$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang\"
        [target.armv7-linux-androideabi]
        ar = \"$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/arm-linux-androideabi-ar\"
        linker = \"$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi19-clang\"
        [target.i686-linux-android]
        ar = \"$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android-ar\"
        linker = \"$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android19-clang\"
        [target.x86_64-linux-android]
        ar = \"$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android-ar\"
        linker = \"$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android21-clang\"" >> "/home/$SUDO_USER/.cargo/config"

ln -sfn $ANDROID_SDK_ROOT/ndk/25.2.9519653 $ANDROID_NDK

# install kotlin
snap install --classic kotlin