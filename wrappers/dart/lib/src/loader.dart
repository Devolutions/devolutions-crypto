import 'dart:ffi';
import 'dart:io';

/// Loads the native Devolutions Crypto library
///
/// This function attempts to load the native library from various locations
/// based on the current platform. The library is expected to be bundled with
/// the Dart package in the `lib/native/` directory.
DynamicLibrary loadDevolutionsCryptoLib() {
  const libName = 'devolutions_crypto_uniffi';

  if (Platform.isWindows) {
    return _loadWindowsLib(libName);
  } else if (Platform.isLinux) {
    return _loadLinuxLib(libName);
  } else if (Platform.isMacOS) {
    return _loadMacOSLib(libName);
  } else if (Platform.isAndroid) {
    return _loadAndroidLib(libName);
  } else if (Platform.isIOS) {
    return _loadIOSLib(libName);
  } else {
    throw UnsupportedError(
        'Platform ${Platform.operatingSystem} is not supported');
  }
}

DynamicLibrary _loadWindowsLib(String libName) {
  // Try loading from package location
  try {
    return DynamicLibrary.open('lib/native/windows-x64/$libName.dll');
  } catch (_) {
    // Fall back to system path
    return DynamicLibrary.open('$libName.dll');
  }
}

DynamicLibrary _loadLinuxLib(String libName) {
  // Try loading from package location
  try {
    return DynamicLibrary.open('lib/native/linux-x64/lib$libName.so');
  } catch (_) {
    // Fall back to system path
    return DynamicLibrary.open('lib$libName.so');
  }
}

DynamicLibrary _loadMacOSLib(String libName) {
  // Try loading from package location based on architecture
  final isArm = Platform.version.contains('arm64');
  final arch = isArm ? 'arm64' : 'x64';

  try {
    return DynamicLibrary.open('lib/native/macos-$arch/lib$libName.dylib');
  } catch (_) {
    // Fall back to system path
    return DynamicLibrary.open('lib$libName.dylib');
  }
}

DynamicLibrary _loadAndroidLib(String libName) {
  // On Android, the library is bundled in the APK and loaded by the system
  // The system determines the correct architecture automatically
  return DynamicLibrary.open('lib$libName.so');
}

DynamicLibrary _loadIOSLib(String libName) {
  // On iOS, the library is bundled in the app bundle
  // Try both possible locations
  try {
    return DynamicLibrary.process();
  } catch (_) {
    return DynamicLibrary.open('lib$libName.dylib');
  }
}
