# devolutions-crypto
[![Build Status](https://dev.azure.com/devolutions-net/Open%20Source/_apis/build/status/devolutions-crypto?branchName=master)](https://dev.azure.com/devolutions-net/Open%20Source/_build/latest?definitionId=170&branchName=master) [![npm version](https://img.shields.io/npm/v/devolutions-crypto.svg?style=flat)](https://npmjs.org/package/devolutions-crypto "View this project on npm")

This folder contains the TypeScript unit tests for the library. You can also use them as usage examples.

## Test Framework

Tests use the **Node.js native test runner** with TypeScript support via `tsx`. This provides a modern, zero-dependency testing solution with built-in assertions.

## Build Native Library

```bash
cd ..
./wasm_build.sh
```

## Run Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch
```

## Test Files

- `asymmetric.ts` - Asymmetric encryption and key exchange tests
- `conformity.ts` - Cross-language compatibility tests
- `hashing.ts` - Password hashing tests
- `secret-sharing.ts` - Shamir's Secret Sharing tests
- `signature.ts` - Digital signature tests
- `symmetric.ts` - Symmetric encryption tests
- `utils.ts` - Key generation, derivation, and encoding tests