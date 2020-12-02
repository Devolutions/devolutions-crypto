#!/bin/bash
cd `dirname "$0"`
wasm-pack build ../../devolutions-crypto --out-dir ../wrappers/wasm/dist/bundler --target bundler -- --features=wbindgen
wasm-pack build ../../devolutions-crypto --out-dir ../wrappers/wasm/dist/node --target nodejs -- --features=wbindgen
