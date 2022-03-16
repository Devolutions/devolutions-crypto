# devolutions-crypto
[![Build Status](https://github.com/Devolutions/devolutions-crypto/actions/workflows/ci.yml/badge.svg)]
Cryptographic library used in Devolutions products. It is made to be fast, easy to use and misuse-resistant.

# Usage
* [Overview](#overview)
* [Ciphertext Module](#ciphertext)
    * [Symmetric Encryption](#symmetric)
    * [Asymmetric Encryption](#asymmetric)
* [Key Module](#key)
    * [Key Generation/Derivation](#generationderivation)
    * [Key Exchange](#key-exchange)
* [PasswordHash Module](#passwordhash)
* [SecretSharing Module](#secretsharing)
* [Signature Module](#signature)
    * [Generating Key Pairs](#generating-key-pairs)
    * [Signing data](#signing-data)
    * [Signature Verification](#verifying-the-signature)
* [Utils Module](#utils)
    * [Key Generation](#key-generation)
    * [Key Derivation](#key-derivation)
    

## Overview

The library is splitted into multiple modules, which are explained below.

## Ciphertext

This module contains everything related to encryption. You can use it to encrypt and decrypt data using either a shared key of a keypair.

### Symmetric

```C#
using Devolutions.Cryptography;

byte[] key = Managed.GenerateKey(32);

byte[] data = Utils.StringToUtf8ByteArray("somesecretdata");

byte[] encrypted_data = Managed.Encrypt(data, key, CipherVersion.Latest);

byte[] decrypted_data = Managed.Decrypt(encrypted_data, key);
```

### Asymmetric
Here, you will need a `PublicKey` to encrypt data and the corresponding 
`PrivateKey` to decrypt it. You can generate them by using `GenerateKeyPair` 
or `DeriveKeyPair` in the [Key module](#key).

```C#
using Devolutions.Cryptography;

KeyPair keypair = Managed.GenerateKeyPair();

byte[] data = Utils.StringToUtf8ByteArray("somesecretdata");

byte[] encrypted_data = Managed.EncryptAsymmetric(data, keypair.PublicKey, CipherVersion.Latest);

byte[] decrypted_data = Managed.DecryptAsymmetric(data, keypair.PrivateKey);
```

### Generation/Derivation

You have two ways to generate a `KeyPair`: Using `GenerateKeyPair` will generate a random one, using `DeriveKeyPair` will derive one from another password or key along with derivation parameters(including salt). Except in specific circumstances, you should use `GenerateKeyPair`.  

Asymmetric keys have two uses. They can be used to [encrypt and decrypt data](##asymmetric) and to perform a [key exchange](#key-exchange).

#### `Generate Key Pair`
```C#
using Devolutions.Cryptography;

KeyPair keypair = Managed.GenerateKeyPair();
```

#### `DeriveKeyPair`
```C#
using Devolutions.Cryptography;

Argon2Parameters parameters = Managed.GetDefaultArgon2Parameters();

KeyPair keypair = Managed.DeriveKeyPair(Utils.StringToUtf8ByteArray("thisisapassword"), parameters);
```

### Key Exchange

The goal of using a key exchange is to get a shared secret key between
two parties without making it possible for users listening on the conversation
to guess that shared key.
1. Alice and Bob generates a `KeyPair` each.
2. Alice and Bob exchanges their `PublicKey`.
3. Alice mix her `PrivateKey` with Bob's `PublicKey`. This gives her the shared key.
4. Bob mixes his `PrivateKey` with Alice's `PublicKey`. This gives him the shared key.
5. Both Bob and Alice has the same shared key, which they can use for symmetric encryption for further communications.

```C#
using Devolutions.Cryptography;

KeyPair bob_keypair = Managed.GenerateKeyPair();
KeyPair alice_keypair = Managed.GenerateKeyPair();

byte[] bob_shared = Managed.MixKeyExchange(bob_keypair.PrivateKey, alice_keypair.PublicKey);

byte[] alice_shared = Managed.MixKeyExchange(alice_keypair.PrivateKey, bob_keypair.PublicKey);
```

## PasswordHash
You can use this module to hash a password and validate it afterward. This is the recommended way to verify a user password on login.

```C#
using Devolutions.Cryptography;

byte[] password = Utils.StringToUtf8ByteArray("somesuperstrongpa$$w0rd!");

byte[] hashed_password = Managed.HashPassword(password, 10000);
```

## SecretSharing
This module is used to generate a key that is splitted in multiple `Share`
and that requires a specific amount of them to regenerate the key.  
You can think of it as a "Break The Glass" scenario. You can
generate a key using this, lock your entire data by encrypting it
and then you will need, let's say, 3 out of the 5 administrators to decrypt
the data. That data could also be an API key or password of a super admin account.

```c#
using Devolutions.Cryptography;
using System.Linq;

// You want a key of 32 bytes, splitted between 5 people, and I want a 
// minimum of 3 of these shares to regenerate the key.
byte[][] shares = Managed.GenerateSharedKey(5, 3, 32);

byte[] key = Managed.JoinShares(shares.Skip(2).ToArray());
```

## Signature
This module is used to sign data using a keypair to certify its authenticity. 

###  Generating Key Pairs
```c#
using Devolutions.Cryptography;
using System.Linq;

SigningKeyPair keypair = Managed.GenerateSigningKeyPair();
```
### Signing Data
```c#
byte[] dataToSign = System.Text.Encoding.UTF8.GetBytes("some data");

byte[] signature = Managed.Sign(dataToSign, keypair);
```

### Verifying the signature
```c#
byte[] dataToVerify = System.Text.Encoding.UTF8.GetBytes("some data");

bool valid = Managed.VerifySignature(dataToVerify, keypair.GetPublicKey(), signature);
```


## Utils

These are a bunch of functions that can
be useful when dealing with the library.

### Key Generation

This is a method used to generate a random key. In almost all case, the `keySize` parameter should be 32.

```C#
using Devolutions.Cryptography;

byte[] key = Managed.GenerateKey(32);
```

### Key Derivation

This is a method used to generate a key from a password or another key. Useful for password-dependant cryptography. Salt should be a random 16 bytes array if possible and iterations should be 10000 or configurable by the user.

```C#
using Devolutions.Cryptography;

byte[] key = Utils.StringToUtf8ByteArray("this is a secret password");
byte[] salt = Managed.GenerateKey(16);
uint iterations = 10000;
uint length = 32;

byte[] new_key = Managed.DeriveKey(key, salt, iterations, length);
```

# Underlying algorithms
As of the current version:
 * Symmetric cryptography uses XChaCha20Poly1305
 * Asymmetric cryptography uses Curve25519.
 * Asymmetric encryption uses ECIES.
 * Key exchange uses x25519, or ECDH over Curve25519
 * Password Hashing uses PBKDF2-HMAC-SHA2-256
 * Secret Sharing uses Shamir Secret sharing over GF256

