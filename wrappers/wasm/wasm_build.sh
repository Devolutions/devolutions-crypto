#!/bin/bash
cd `dirname "$0"`
wasm-pack build ../../devolutions-crypto --out-dir ../wrappers/wasm/pkg
wasm-pack pack