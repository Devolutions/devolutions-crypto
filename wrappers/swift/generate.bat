rmdir /s /q .\output

cargo run -p uniffi-bindgen generate --library "..\..\target\release\uniffi_lib.dll"  --language swift -o output --no-format

ren ..\..\target\release\libuniffi_lib.dll.a uniffi_lib.lib

cd output

swiftc -module-name uniffi_lib -emit-library -o uniffi_lib.dll -emit-module -emit-module-path ./lib_output/uniffi_lib.swiftmodule -parse-as-library -L ../../../target/release/ -luniffi_lib -Xcc -fmodule-map-file="C:\dev\git\devolutions-crypto\wrappers\swift\output\uniffi_libFFI.modulemap" uniffi_lib.swift 


