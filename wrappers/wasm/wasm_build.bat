wasm-pack build ../../ --out-dir ./wrappers/wasm/dist/bundler --target bundler --scope devolutions -- --features=wbindgen
wasm-pack build ../../ --out-dir ./wrappers/wasm/dist/node --target nodejs --scope devolutions -- --features=wbindgen
wasm-pack build ../../ --out-dir ./wrappers/wasm/dist/web --target web --scope devolutions -- --features=wbindgen
wasm-pack build ../../ --out-dir ./wrappers/wasm/dist/no-modules --target no-modules --scope devolutions -- --features=wbindgen
