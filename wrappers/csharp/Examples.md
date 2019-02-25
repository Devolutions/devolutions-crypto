# Encrypt
###

```csharp

// With strings
string encrypted_string = Devolutions.Cryptography.Encrypt("mysupersecretdata", "mysecretpassword");

// With bytes
byte[] data = new byte[] { 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20 };
byte[] key = new byte[] { 0x40, 0x40, 0x70, 0x20, 0x80, 0x30, 0x50 };

byte[] encrypted_data = Devolutions.Cryptography.Encrypt(data, key);

```

# Decrypt
###

```csharp
// With strings
string decrypted_string = Devolutions.Cryptography.Decrypt(encrypted_string, "mysecretpassword");

//With bytes
byte[] key = new byte[] { 0x40, 0x40, 0x70, 0x20, 0x80, 0x30, 0x50 };

byte[] dencrypted_data = Devolutions.Cryptography.Decrypt(encrypted_data, key);

```

# Password Hashing and Verification
###

```csharp

string hash_result = Devolutions.Cryptography.HashPassword("mysupersecretpassword", 30000)

bool result = Devolutions.Cryptography.VerifyPassword("mysupersecretpassword", hash_result);

```

# Key Exchange
###

```csharp
KeyExchange bob = Devolutions.Cryptography.GenerateKeyExchange();
KeyExchange alice = Devolutions.Cryptography.GenerateKeyExchange();

byte[] sharedAlice = MixKeyExchange(bob.PublicKey, alice.PrivateKey)
byte[] sharedBob = MixKeyExchange(alice.PublicKey, bob.PrivateKey)

if(sharedAlice == sharedBob)
{
  // Success
}
```
