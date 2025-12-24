# Known Issues

## Native Library Loading

The generated Dart bindings use Dart's **native assets system** which is still under active development.

### Current Status

- ✅ Bindings generate successfully (2362 lines)
- ✅ Code compiles without errors
- ✅ All types and enums are available
- ✅ Native libraries build successfully
- ⚠️ **Native library loading at runtime needs stable API**

### Issue

The generated code expects native libraries via Dart's native assets system:
```dart
const _uniffiAssetId = "package:uniffi/uniffi:uniffi_devolutions_crypto";
```

**Problem:** Dart's native assets system is still evolving:
- `native_assets_cli` package is discontinued (replaced by `hooks`)
- New `hooks` package API is not yet stable/documented
- uniffi-dart generates code for native assets but the configuration API keeps changing

### Attempted Solution

A `hook/build.dart` file was created but cannot be fully implemented because:
1. The native assets API is in flux (packages being replaced/redesigned)
2. Documentation for the stable API is not yet available
3. uniffi-dart itself is waiting for the API to stabilize

### Workaround Options

#### Option 1: Wait for Dart Native Assets Stabilization (Recommended)

Wait for Dart's native assets system to stabilize and for uniffi-dart to provide proper configuration examples. This is the most future-proof approach.

**Status:** The Dart team is actively working on native assets. Check:
- [Dart native assets tracking issue](https://github.com/dart-lang/sdk/issues/50565)
- [uniffi-dart issues](https://github.com/Uniffi-Dart/uniffi-dart/issues)

#### Option 2: Modify uniffi-dart Generator

Fork uniffi-dart and modify the code generator to use traditional `DynamicLibrary.open()` instead of native assets. This would make it work immediately but loses future native assets benefits.

**Steps:**
1. Fork uniffi-dart
2. Modify the Dart binding generator to emit `DynamicLibrary.open()` calls
3. Use your fork in `uniffi/dart-bindgen/Cargo.toml`

#### Option 3: Create a Wrapper Layer

Create a Dart wrapper that manually loads the library and provides the same API:
1. Keep the generated bindings
2. Create manual FFI loading code
3. Bridge between your loader and the generated code

This is complex but allows using the current setup.

### Testing Without Native Assets

You can test that bindings compile:
```dart
import 'package:devolutions_crypto/devolutions_crypto.dart';

void main() {
  // Types and enums are available
  print(CiphertextVersion.values);
  print(DataType.values);
}
```

But actual crypto operations will fail until native library loading is configured.

## Next Steps

1. Research Dart native assets system
2. Create appropriate `hook/build.dart` configuration
3. Or contribute to uniffi-dart to add traditional DynamicLibrary support
4. Test on multiple platforms

## References

- [Dart Native Assets](https://dart.dev/guides/libraries/native-assets)
- [uniffi-dart GitHub](https://github.com/Uniffi-Dart/uniffi-dart)
- [Native Assets CLI](https://pub.dev/packages/native_assets_cli)
