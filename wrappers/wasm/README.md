# WebAssembly Wrapper
This folder is here to help you build the webassembly module.
Note that these instructions are meant for linux, but might work on other platforms too.

## Prerequisites
First you need to install `wasm-pack`.
```
cargo install wasm-pack
```
Then, add it too the PATH by adding this line to your .bashrc
```
export PATH=/$HOME/.cargo/bin:$PATH
```

## Build
Then simply run the `wasm-build.sh` script:
```
./wasm-build.sh
```

This will build the module in the `pkg/` directory.

## Use
Refer to the `example/` folder for an example on how to use it with webpack. I'll try to get an angular example working when I have the time, but if you find out how please let me know!

## Current State
Currently, the webassembly module implements the same functionnalities as the native version, while keeping the build system pretty easy to use. It is also part of the CI. On a security standpoint it is as secure as the native one and is also pretty fast.  
Please note however that we still consider it to be beta as the API is not final yet and might still change, so we won't publish it to npm for now.