#!/bin/bash
cd `dirname "$0"`
wasm-pack build --release --no-typescript --target no-modules --out-dir ../wasm/
