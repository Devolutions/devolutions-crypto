#!/bin/bash
cd `dirname "$0"`
wasm-pack build ../../devolutionscrypto --out-dir ../wrappers/wasm/pkg
wasm-pack pack