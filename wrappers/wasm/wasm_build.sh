#!/bin/bash
cd `dirname "$0"`
wasm-pack build ../../devolutions-crypto --release --out-dir ../wrappers/wasm/pkg
wasm-pack pack
