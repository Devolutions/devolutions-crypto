# Encrypt
###

```csharp
  string encrypt = Cryptography.EncryptWithPasswordAsString("secretdata", "secretpass");
```

# Decrypt
###

```csharp
  string decrypt = Cryptography.DecryptWithPasswordAsString(string_encrypt_result, "secretpass");
```
