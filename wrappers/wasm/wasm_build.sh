#!/bin/bash
cd `dirname "$0"`
wasm-pack build ../../ --out-dir ./wrappers/wasm/dist/bundler --target bundler --scope devolutions -- --features=wbindgen
wasm-pack build ../../ --out-dir ./wrappers/wasm/dist/node --target nodejs --scope devolutions -- --features=wbindgen
wasm-pack build ../../ --out-dir ./wrappers/wasm/dist/web --target web --scope devolutions -- --features=wbindgen
wasm-pack build ../../ --out-dir ./wrappers/wasm/dist/no-modules --target no-modules --scope devolutions -- --features=wbindgen

sed -i 's/"@devolutions\/devolutions-crypto"/"@devolutions\/devolutions-crypto-web"/' ./dist/web/package.json