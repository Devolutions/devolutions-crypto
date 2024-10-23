cd "..\..\uniffi\devolutions-crypto-uniffi\"
cargo build --release

cd "../uniffi-bindgen"
cargo run -p uniffi-bindgen generate --library "..\..\target\release\devolutions_crypto_uniffi.dll"  --language kotlin -o ../../wrappers/kotlin/lib/src/main/kotlin --no-format

cd "../../"

copy ".\target\release\devolutions_crypto_uniffi.dll" ".\wrappers\kotlin\lib\src\main\resources\win32-x86-64\"
