# Android

Install Android Studio

On the first screen go to **Configure > SDK Manager > Appearance & Behaviour > System Settings > Android SDK > SDK Tools**

Install the following :

```
NDK
CMake
LLDB
```

Configure the following environment variables (The path might change depending on the OS) :

```
export ANDROID_HOME=/home/$USER/Android/Sdk
export NDK_HOME=$ANDROID_HOME/ndk-bundle
```

Add the following targets in you **.cargo/config** file and replace <NDK_HOME> with the path of the environment variable:

```
[target.aarch64-linux-android]
ar = "<NDK_HOME>/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android-ar"
linker = "<NDK_HOME>/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang"
 

[target.armv7-linux-androideabi]
ar = "<NDK_HOME>/toolchains/llvm/prebuilt/linux-x86_64/bin/arm-linux-androideabi-ar"
linker = "<NDK_HOME>/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi26-clang"


[target.i686-linux-android]
ar = "<NDK_HOME>/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android-ar"
linker = "<NDK_HOME>/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android26-clang"
```

Install the required targets :

```
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android
```

Once configured run :

```
python GeneratePackage.py ANDROID
```




