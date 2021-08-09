#!/bin/bash
cd `dirname "$0"`
wasm-pack build ../../devolutions-crypto --out-dir ../wrappers/wasm/dist/bundler --target bundler --scope devolutions -- --features=wbindgen
wasm-pack build ../../devolutions-crypto --out-dir ../wrappers/wasm/dist/node --target nodejs --scope devolutions -- --features=wbindgen
