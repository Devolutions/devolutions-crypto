import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';

void main(List<String> arguments) async {
  await build(arguments, (input, output) async {
    if (!input.config.buildCodeAssets) {
      return;
    }

    final packageName = input.packageName;
    final packageRoot = input.packageRoot.toFilePath();
    final targetOS = input.config.code.targetOS;
    final targetArch = input.config.code.targetArchitecture;

    // Determine the library file based on OS
    String getLibFileName(OS os) {
      switch (os) {
        case OS.windows:
          return 'devolutions_crypto_uniffi.dll';
        case OS.linux:
        case OS.android:
          return 'libdevolutions_crypto_uniffi.so';
        case OS.macOS:
        case OS.iOS:
          return 'libdevolutions_crypto_uniffi.dylib';
        default:
          throw UnsupportedError('Unsupported OS: $os');
      }
    }

    // Determine the directory based on OS and architecture
    String getLibDir(OS os, Architecture arch) {
      switch (os) {
        case OS.windows:
          return 'lib/native/windows-x64';
        case OS.linux:
          return 'lib/native/linux-x64';
        case OS.macOS:
          if (arch == Architecture.arm64) {
            return 'lib/native/macos-arm64';
          }
          return 'lib/native/macos-x64';
        case OS.android:
          switch (arch) {
            case Architecture.arm64:
              return 'lib/native/android-arm64-v8a';
            case Architecture.arm:
              return 'lib/native/android-armeabi-v7a';
            case Architecture.x64:
              return 'lib/native/android-x86-64';
            case Architecture.ia32:
              return 'lib/native/android-x86';
            default:
              throw UnsupportedError('Unsupported Android arch: $arch');
          }
        case OS.iOS:
          if (arch == Architecture.arm64) {
            return 'lib/native/ios-arm64';
          }
          return 'lib/native/ios-x64-simulator';
        default:
          throw UnsupportedError('Unsupported OS: $os');
      }
    }

    final libDir = getLibDir(targetOS, targetArch);
    final libFileName = getLibFileName(targetOS);
    final libPath = '$packageRoot/$libDir/$libFileName';
    final libFile = File(libPath);

    if (!libFile.existsSync()) {
      throw Exception(
        'Native library not found at: $libPath\n\n'
        'Please build the native library first:\n'
        '  cd $packageRoot\n'
        '  make ${targetOS.toString().split('.').last}\n\n'
        'Or see the README for build instructions.',
      );
    }

    // Register the code asset
    // Asset name must match the generated _uniffiAssetId format:
    // "package:devolutions_crypto/uniffi:devolutions_crypto_uniffi"
    output.assets.code.add(CodeAsset(
      package: packageName,
      name: 'uniffi:devolutions_crypto_uniffi',
      linkMode: DynamicLoadingBundled(),
      file: libFile.uri,
    ));
  });
}
