# Encrypt
###

```csharp
  string encrypt = Devolutions.Cryptography.Managed.EncryptWithPasswordAsString("secretdata", "secretpass");
```

# Decrypt
###

```csharp
  string decrypt = Devolutions.Cryptography.Managed.DecryptWithPasswordAsString(encrypt, "secretpass");
```
