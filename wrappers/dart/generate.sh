#!/bin/bash
# Script to generate Dart bindings using uniffi-dart
# See: https://github.com/Uniffi-Dart/uniffi-dart

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=== Devolutions Crypto Dart Bindings Generator ==="
echo ""

# Build the Rust library
echo "Step 1: Building devolutions-crypto-uniffi library..."
cd "$ROOT_DIR"
cargo build -p devolutions-crypto-uniffi
echo "✓ Library built successfully"
echo ""

# Determine platform and library path
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    LIB_EXT="so"
    LIB_PREFIX="lib"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    LIB_EXT="dylib"
    LIB_PREFIX="lib"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
    LIB_EXT="dll"
    LIB_PREFIX=""
else
    echo "ERROR: Unsupported platform: $OSTYPE"
    exit 1
fi

LIB_PATH="$ROOT_DIR/target/debug/${LIB_PREFIX}devolutions_crypto_uniffi.$LIB_EXT"

if [ ! -f "$LIB_PATH" ]; then
    echo "ERROR: Library not found at: $LIB_PATH"
    exit 1
fi

# Generate Dart bindings using custom bindgen tool
echo "Step 2: Generating Dart bindings..."
cd "$ROOT_DIR/uniffi/dart-bindgen"

UDL_FILE="$ROOT_DIR/uniffi/devolutions-crypto-uniffi/src/devolutions_crypto.udl"
BINDINGS_OUTPUT="$SCRIPT_DIR/lib/src/generated"

cargo run --release -- "$UDL_FILE" "$BINDINGS_OUTPUT"

echo "✓ Dart bindings generated"
echo ""

# Install dependencies and format
cd "$SCRIPT_DIR"
echo "Step 3: Installing Dart dependencies..."
dart pub get
echo ""

echo "Step 4: Formatting generated code..."
dart format lib/
echo ""

echo "✓✓✓ SUCCESS! ✓✓✓"
echo ""
echo "Dart bindings have been generated in: $BINDINGS_OUTPUT"
echo ""
echo "Next steps:"
echo "  1. Review the generated files in lib/src/generated/"
echo "  2. Build native libraries for target platforms (see Makefile)"
echo "  3. Run tests: dart test"
echo "  4. Run example: dart run example/devolutions_crypto_example.dart"
