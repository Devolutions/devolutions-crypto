#pragma warning disable SA1600 // Elements should be documented
namespace Devolutions.Crypto.Tests
{
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    using System;
    using System.Text;

    using Devolutions.Cryptography;
    using Devolutions.Cryptography.Argon2;
    using Devolutions.Cryptography.Signature;

    [TestClass]
    public class TestManaged
    {
        [TestMethod]
        public void ByteArrayToString()
        {
            string? conversionResult = Utils.ByteArrayToUtf8String(TestData.BytesTestData);
            Assert.AreEqual(conversionResult, TestData.StringTestData);
        }

        [TestMethod]
        public void Decode()
        {
            byte[] data = Utils.DecodeFromBase64(TestData.Base64TestData)!;
            Assert.AreEqual(Convert.ToBase64String(data), Convert.ToBase64String(TestData.BytesTestData));
        }

        [TestMethod]
        public void Decrypt()
        {
            byte[]? decryptResult = Managed.Decrypt(TestData.EncryptedData, TestData.BytesTestKey);
            string? encodedByteArrayToUtf8String = Utils.ByteArrayToUtf8String(decryptResult);
            Assert.AreEqual(encodedByteArrayToUtf8String, TestData.Base64TestData);
        }

        [TestMethod]
        public void DecryptAsymmetric()
        {
            byte[] encryptedData = Convert.FromBase64String("DQwCAAIAAgD5rUXkPQO55rzI69WSxtVTA43lDXougn6BxJ7evqf+Yq+SEGXZxpE49874fz/aEk39LTnh1yWnY2VNoAAqKVB5CWZryd6SSld8Sx8v");
            byte[]? decryptedData = Managed.DecryptAsymmetric(encryptedData, TestData.AlicePrivateKey);

            Assert.IsNotNull(decryptedData);
            Assert.AreEqual(Encoding.UTF8.GetString(decryptedData), "test");
        }

        [TestMethod]
        public void DecryptWithKey()
        {
            byte[]? decryptResult = Managed.DecryptWithKey(TestData.EncryptedData, TestData.BytesTestKey);
            string? decryptResultString = Utils.ByteArrayToUtf8String(decryptResult);
            Assert.AreEqual(decryptResultString, TestData.Base64TestData);
        }

        [TestMethod]
        public void DecryptWithKeyAsUtf8String()
        {
            string? decryptResultString = Managed.DecryptWithKeyAsUtf8String(TestData.EncryptedData, TestData.BytesTestKey);
            Assert.AreEqual(decryptResultString, TestData.Base64TestData);
        }

        [TestMethod]
        public void DecryptWithPassword()
        {
            string encryptedDataAsBase64 = "DQwCAAAAAgDutPWBLPHG0+ocNw+Yzs6xygGOeOlNPOAjbYDdbJKjPRnEP8HuDN7Y3h3dCoH81Szf3tCf3mNf";
            string password = "testPa$$";
            byte[]? decryptResult = Managed.DecryptWithPassword(encryptedDataAsBase64, password, 10000);
            string? decryptResultString = Utils.ByteArrayToUtf8String(decryptResult);
            Assert.AreEqual(decryptResultString, "test Ciph3rtext");
        }

        [TestMethod]
        public void DecryptWithPasswordAsUtf8String()
        {
            string encryptedDataAsBase64 = "DQwCAAAAAgCoE9Y3m06QaPSAiL2qegthcm0+zZWt4fXbdqcefkzD6y8pnWsMzLkx/32t";
            string? decryptResultString = Managed.DecryptWithPasswordAsUtf8String(encryptedDataAsBase64, TestData.TestPassword, 10000);
            Assert.AreEqual(decryptResultString, TestData.StringTestData);
        }

        [TestMethod]
        public void DerivePassword()
        {
            byte[] derivedPassword = Managed.DerivePassword(TestData.Base64TestData, null, 100);
            Assert.AreEqual(Convert.ToBase64String(TestData.TestDeriveBytes), Convert.ToBase64String(derivedPassword));
        }

        [TestMethod]
        public void Encode()
        {
            string? encodedArrayToBase64String = Utils.EncodeToBase64String(TestData.BytesTestData);
            Assert.AreEqual(encodedArrayToBase64String, TestData.Base64TestData);
        }

        [TestMethod]
        public void Encrypt()
        {
            byte[] base64DataAsUtf8ByteArray = Utils.StringToUtf8ByteArray(TestData.Base64TestData2);
            byte[]? encryptResult = Managed.Encrypt(base64DataAsUtf8ByteArray, TestData.BytesTestKey);
            Assert.IsTrue(Utils.ValidateHeader(encryptResult, DataType.Cipher));

            byte[]? decryptResult = Managed.Decrypt(encryptResult, TestData.BytesTestKey);
            string? decryptResultAsUtf8String = Utils.ByteArrayToUtf8String(decryptResult);
            Assert.AreEqual(decryptResultAsUtf8String, TestData.Base64TestData2);
        }

        [TestMethod]
        public void EncryptAsymmetric()
        {
            byte[] dataToEncrypt = "test"u8.ToArray();
            byte[]? encryptedData = Managed.EncryptAsymmetric(dataToEncrypt, TestData.AlicePublicKey);

            Assert.IsNotNull(encryptedData);
            Assert.AreEqual(encryptedData.Length, 84);
        }

        [TestMethod]
        public void EncryptBase64WithPassword()
        {
            byte[]? encryptedData = Managed.EncryptBase64WithPassword(TestData.Base64TestData, TestData.TestPassword);
            Assert.IsTrue(Utils.ValidateHeader(encryptedData, DataType.Cipher));

            byte[]? decryptResult = Managed.DecryptWithPassword(encryptedData, TestData.TestPassword);
            string? decryptResultString = Utils.ByteArrayToUtf8String(decryptResult);
            Assert.AreEqual(decryptResultString, TestData.StringTestData);
        }

        [TestMethod]
        public void EncryptBase64WithPasswordAsString()
        {
            string? encryptResultString = Managed.EncryptBase64WithPasswordAsString(TestData.Base64TestData, TestData.TestPassword);
            string? decryptResultAsUtf8String = Managed.DecryptWithPasswordAsUtf8String(encryptResultString, TestData.TestPassword);
            Assert.AreEqual(decryptResultAsUtf8String, TestData.StringTestData);
        }

        [TestMethod]
        public void EncryptDecryptWithKeyAsBase64String()
        {
            byte[] encodedData = Utils.StringToUtf8ByteArray(TestData.StringTestData);
            byte[] encodedPassword = Utils.StringToUtf8ByteArray(TestData.TestPassword);
            string? encryptResultAsBase64String = Managed.EncryptWithKeyAsBase64String(encodedData, encodedPassword);
            Assert.IsNotNull(encryptResultAsBase64String);

            string? decryptResult = Managed.DecryptWithKeyAsUtf8String(encryptResultAsBase64String, encodedPassword);
            Assert.AreEqual(decryptResult, TestData.StringTestData);
        }

        [TestMethod]
        public void EncryptWithKeyDecryptWithKey()
        {
            byte[] encodedData = Utils.StringToUtf8ByteArray(TestData.StringTestData);
            byte[] encodedPassword = Utils.StringToUtf8ByteArray(TestData.TestPassword);
            byte[]? encryptResultArray = Managed.EncryptWithKey(encodedData, encodedPassword);
            Assert.IsNotNull(encryptResultArray);

            byte[]? decryptResult = Managed.DecryptWithKey(encryptResultArray, encodedPassword);
            string? decryptResultAsUtf8String = Utils.ByteArrayToUtf8String(decryptResult);
            Assert.AreEqual(decryptResultAsUtf8String, TestData.StringTestData);
        }

        [TestMethod]
        public void EncryptWithPasswordAsBase64String()
        {
            byte[] encodedDataAsUtf8ByteArray = Utils.StringToUtf8ByteArray(TestData.StringTestData);
            string? encryptResultAsBase64String = Managed.EncryptWithPasswordAsBase64String(encodedDataAsUtf8ByteArray, TestData.TestPassword);
            string? decryptResultAsUtf8String = Managed.DecryptWithPasswordAsUtf8String(encryptResultAsBase64String, TestData.TestPassword);
            Assert.AreEqual(decryptResultAsUtf8String, TestData.StringTestData);
        }

        [TestMethod]
        public void EncryptDecryptWithPasswordAsBase64String()
        {
            byte[] base64EncodedToUtf8ByteArray = Utils.StringToUtf8ByteArray(TestData.Base64TestData);
            string password = "pwd";
            string? encryptResultAsBase64String = Managed.EncryptWithPasswordAsBase64String(base64EncodedToUtf8ByteArray, password, 100);
            string? decryptionResultAsUtf8String = Managed.DecryptWithPasswordAsUtf8String(encryptResultAsBase64String, password, 100);
            Assert.AreEqual(decryptionResultAsUtf8String, TestData.Base64TestData);
        }

        [TestMethod]
        public void GenerateKey()
        {
            byte[] firstKey = Managed.GenerateKey(32);
            Assert.AreEqual(32, firstKey.Length);
            byte[] secondKey = Managed.GenerateKey(32);
            Assert.AreNotEqual(firstKey, secondKey);
        }

        [TestMethod]
        public void GenerateKeyPair()
        {
            KeyPair bob = Managed.GenerateKeyPair();
            KeyPair alice = Managed.GenerateKeyPair();
            byte[] bobMix = Managed.MixKeyExchange(bob.PrivateKey, alice.PublicKey);
            byte[] aliceMix = Managed.MixKeyExchange(alice.PrivateKey, bob.PublicKey);
            Assert.AreEqual(Convert.ToBase64String(bobMix), Convert.ToBase64String(aliceMix));
        }

        [TestMethod]
        public void GenerateSecretKeyObject()
        {
            SecretKey key = Managed.GenerateSecretKey();
            Assert.IsNotNull(key.ToByteArray());
            Assert.IsTrue(key.ToByteArray().Length > 0);
        }

        [TestMethod]
        public void EncryptDecryptWithSecretKey()
        {
            byte[] plaintext = "test secret message"u8.ToArray();
            SecretKey key = Managed.GenerateSecretKey();

            byte[]? ciphertext = Managed.Encrypt(plaintext, key);
            Assert.IsNotNull(ciphertext);
            Assert.IsTrue(Utils.ValidateHeader(ciphertext, DataType.Cipher));

            byte[]? decrypted = Managed.Decrypt(ciphertext, key);
            Assert.IsNotNull(decrypted);
            Assert.AreEqual("test secret message", Encoding.UTF8.GetString(decrypted));
        }

        [TestMethod]
        public void EncryptDecryptWithSecretKeyAndAad()
        {
            byte[] plaintext = "test secret message"u8.ToArray();
            byte[] aad = "public metadata"u8.ToArray();
            byte[] wrongAad = "tampered metadata"u8.ToArray();
            SecretKey key = Managed.GenerateSecretKey();

            byte[]? ciphertext = Managed.Encrypt(plaintext, key, aad);
            Assert.IsNotNull(ciphertext);

            byte[]? decrypted = Managed.Decrypt(ciphertext, key, aad);
            Assert.IsNotNull(decrypted);
            Assert.AreEqual("test secret message", Encoding.UTF8.GetString(decrypted));

            Assert.ThrowsException<DevolutionsCryptoException>(() => Managed.Decrypt(ciphertext, key, wrongAad));
        }

        [TestMethod]
        public void SecretKeyRoundTrip()
        {
            SecretKey original = Managed.GenerateSecretKey();
            byte[] serialized = original.ToByteArray();
            SecretKey restored = SecretKey.FromByteArray(serialized);

            byte[] plaintext = "round-trip test"u8.ToArray();

            byte[]? ciphertext = Managed.Encrypt(plaintext, original);
            byte[]? decrypted = Managed.Decrypt(ciphertext, restored);

            Assert.IsNotNull(decrypted);
            Assert.AreEqual("round-trip test", Encoding.UTF8.GetString(decrypted));
        }

        [TestMethod]
        public void GenerateSigningKeyPair()
        {
            SigningKeyPair keypair = Managed.GenerateSigningKeyPair();
            byte[] keypairRaw = keypair.ToByteArray();

            Assert.AreEqual(keypairRaw.Length, 72);
        }

        [TestMethod]
        public void Sign()
        {
            SigningKeyPair keypair = SigningKeyPair.FromByteArray(Convert.FromBase64String(TestData.SigningKeyPairb64));
            byte[] data = Encoding.UTF8.GetBytes(TestData.SignTesting);

            byte[]? signature = Managed.Sign(data, keypair);
            Assert.IsNotNull(signature);
            Assert.AreEqual(TestData.SignedTestingb64, Convert.ToBase64String(signature));
        }

        [TestMethod]
        public void VerifySignature()
        {
            byte[] signature = Convert.FromBase64String(TestData.SignedTestingb64);

            SigningKeyPair keypair = SigningKeyPair.FromByteArray(Convert.FromBase64String(TestData.SigningKeyPairb64));
            SigningPublicKey pubkey = SigningPublicKey.FromByteArray(Convert.FromBase64String(TestData.SigningPublicKeyb64));

            bool res = Managed.VerifySignature(Encoding.UTF8.GetBytes(TestData.SignTesting), pubkey, signature);

            Assert.IsTrue(res);
        }

        [TestMethod]
        public void VerifySignature_FailBadData()
        {
            byte[] signature = Convert.FromBase64String(TestData.SignedTestingb64);

            SigningKeyPair keypair = SigningKeyPair.FromByteArray(Convert.FromBase64String(TestData.SigningKeyPairb64));
            SigningPublicKey pubkey = SigningPublicKey.FromByteArray(Convert.FromBase64String(TestData.SigningPublicKeyb64));

            bool res = Managed.VerifySignature("bad data"u8.ToArray(), pubkey, signature);

            Assert.IsFalse(res);
        }

        [TestMethod]
        public void VerifySignature_FailBadKey()
        {
            byte[] signature = Convert.FromBase64String(TestData.SignedTestingb64);

            SigningKeyPair keypair = Managed.GenerateSigningKeyPair();
            SigningPublicKey pubkey = keypair.GetPublicKey();

            bool res = Managed.VerifySignature(Encoding.UTF8.GetBytes(TestData.SignTesting), pubkey, signature);

            Assert.AreEqual(res, false);
        }

        [TestMethod]
        public void VerifySignature_FailBadSignature()
        {
            SigningKeyPair keypair = Managed.GenerateSigningKeyPair();
            byte[]? signature = Managed.Sign(Encoding.UTF8.GetBytes(TestData.SignTesting), keypair);
            Assert.IsNotNull(signature);

            SigningPublicKey pubkey = SigningPublicKey.FromByteArray(Convert.FromBase64String(TestData.SigningPublicKeyb64));

            bool res = Managed.VerifySignature(Encoding.UTF8.GetBytes(TestData.SignTesting), pubkey, signature);

            Assert.IsFalse(res);
        }

        [TestMethod]
        public void GenerateSharedKey()
        {
            const int nbShares = 5;
            const int secretLength = 10;
            const int threshold = 3;
            var result = Managed.GenerateSharedKey(nbShares, threshold, secretLength);
            Assert.IsTrue(result is { Length: 5 } && result[0].Length == 20);
        }

        [TestMethod]
        public void GetDecodedLength()
        {
            int bufferDecodedLength = Utils.GetDecodedBase64StringLength(TestData.Base64TestData);
            Assert.AreEqual(bufferDecodedLength, 3);
        }

        [TestMethod]
        public void GetDefaultArgon2ParametersSizeNative_Default()
        {
            Argon2Parameters defaultArgon2Parameters = Managed.GetDefaultArgon2Parameters();

            Assert.IsTrue(defaultArgon2Parameters != null);
            Assert.IsTrue(defaultArgon2Parameters.Memory == 4096);
        }

        [TestMethod]
        public void GetEncodedLength()
        {
            int stringEncodedLength = Utils.GetEncodedBase64StringLength(TestData.BytesTestData);
            Assert.AreEqual(stringEncodedLength, 4);
        }

        [TestMethod]
        public void HashPassword()
        {
            byte[] firstHash = Managed.HashPassword(TestData.BytesTestKey);
            byte[] secondHash = Managed.HashPassword(TestData.BytesTestData);

            Assert.IsTrue(Managed.VerifyPassword(TestData.BytesTestKey, firstHash));
            Assert.IsFalse(Managed.VerifyPassword(secondHash, firstHash));
        }

        [TestMethod]
        public void HashPasswordV1()
        {
            byte[] hash = Managed.HashPassword(TestData.BytesTestKey, PasswordHashVersion.V1);

            Assert.IsTrue(Managed.VerifyPassword(TestData.BytesTestKey, hash));
            Assert.IsFalse(Managed.VerifyPassword(TestData.BytesTestData, hash));
        }

        [TestMethod]
        public void HashPasswordV2()
        {
            byte[] hash = Managed.HashPassword(TestData.BytesTestKey, PasswordHashVersion.V2);

            Assert.IsTrue(Managed.VerifyPassword(TestData.BytesTestKey, hash));
            Assert.IsFalse(Managed.VerifyPassword(TestData.BytesTestData, hash));
        }

        [TestMethod]
        public void HashPasswordWithParams()
        {
            Argon2Parameters parameters = new()
            {
                Memory = 32,
                Iterations = 2,
            };
            byte[] derivationParams = Managed.GetArgon2DerivationParameters(parameters);

            byte[] hash = Managed.HashPasswordWithParams(TestData.BytesTestKey, derivationParams);
            Assert.IsNotNull(hash);
            Assert.IsTrue(hash.Length > 0);

            Assert.IsTrue(Managed.VerifyPassword(TestData.BytesTestKey, hash));
            Assert.IsFalse(Managed.VerifyPassword(TestData.BytesTestData, hash));
        }

        [TestMethod]
        public void JoinShares()
        {
            var shares = GetSharesKeys();
            var result = Managed.JoinShares(shares);
            var val = Utils.ByteArrayToUtf8String(result);
            Assert.IsTrue(result is { Length: 10 });

            var shares2 = GetSharesKeys2();
            var result2 = Managed.JoinShares(shares2);
            var val2 = Utils.ByteArrayToUtf8String(result2);

            Assert.IsTrue(result2 is { Length: 10 });
            Assert.AreEqual(val, val2);
        }

        [TestMethod]
        public void MixKeyExchange()
        {
            byte[] bobMix = Managed.MixKeyExchange(TestData.BobPrivateKey, TestData.AlicePublicKey);
            byte[] aliceMix = Managed.MixKeyExchange(TestData.AlicePrivateKey, TestData.BobPublicKey);
            Assert.AreEqual(Convert.ToBase64String(bobMix), Convert.ToBase64String(aliceMix));
        }

        [TestMethod]
        public void StringToByteArray()
        {
            byte[] dataEncodedToUtf8ByteArray = Utils.StringToUtf8ByteArray(TestData.StringTestData);
            Assert.AreEqual(Convert.ToBase64String(dataEncodedToUtf8ByteArray), Convert.ToBase64String(TestData.BytesTestData));
        }

        [TestMethod]
        public void ToBase64String()
        {
            string? dataEncodedToBase64String = Utils.EncodeToBase64String(TestData.BytesTestData);
            Assert.AreEqual(dataEncodedToBase64String, TestData.Base64TestData);
        }

        [TestMethod]
        public void VerifyPassword()
        {
            Assert.IsTrue(Managed.VerifyPassword(TestData.BytesTestKey, TestData.TestHash));
        }

        [TestMethod]
        public void DeriveSecretKeyPbkdf2_ReturnsDifferentKeysAndParams()
        {
            byte[] password = "my test password"u8.ToArray();

            KeyDerivationResult result1 = Managed.DeriveSecretKeyPbkdf2(password, 10);
            KeyDerivationResult result2 = Managed.DeriveSecretKeyPbkdf2(password, 10);

            Assert.IsNotNull(result1.SecretKey);
            Assert.IsNotNull(result1.Parameters);

            // Random salt → different params and different derived keys on each call
            CollectionAssert.AreNotEqual(result1.Parameters.ToByteArray(), result2.Parameters.ToByteArray());
            CollectionAssert.AreNotEqual(result1.SecretKey.ToByteArray(), result2.SecretKey.ToByteArray());
        }

        [TestMethod]
        public void DeriveSecretKeyPbkdf2_ParametersRoundTrip()
        {
            byte[] password = "round-trip password"u8.ToArray();

            KeyDerivationResult result = Managed.DeriveSecretKeyPbkdf2(password, 10);

            byte[] paramsBytes = result.Parameters.ToByteArray();
            Assert.IsTrue(paramsBytes.Length > 0);

            // Parameters can be round-tripped through byte array
            DerivationParameters restored = DerivationParameters.FromByteArray(paramsBytes);
            CollectionAssert.AreEqual(paramsBytes, restored.ToByteArray());
        }

        [TestMethod]
        public void DeriveSecretKeyArgon2_WithFixedSalt_ProducesSameKey()
        {
            byte[] password = "argon2 test password"u8.ToArray();

            // Use a pre-serialized Argon2Parameters with a known fixed salt for deterministic derivation
            byte[] fixedParamsBytes = Convert.FromBase64String(TestData.Argon2DefaultParametersb64);
            Argon2Parameters parameters1 = Argon2Parameters.FromByteArray(fixedParamsBytes)!;
            Argon2Parameters parameters2 = Argon2Parameters.FromByteArray(fixedParamsBytes)!;

            KeyDerivationResult result1 = Managed.DeriveSecretKeyArgon2(password, parameters1);
            KeyDerivationResult result2 = Managed.DeriveSecretKeyArgon2(password, parameters2);

            // Same parameters (same salt) + same password → same derived key
            CollectionAssert.AreEqual(result1.SecretKey.ToByteArray(), result2.SecretKey.ToByteArray());
        }

        [TestMethod]
        public void DeriveSecretKeyArgon2_DifferentSalts_ProduceDifferentKeys()
        {
            byte[] password = "argon2 test password"u8.ToArray();

            // Default params generate a random salt on each call
            KeyDerivationResult result1 = Managed.DeriveSecretKeyArgon2(password, Managed.GetDefaultArgon2Parameters());
            KeyDerivationResult result2 = Managed.DeriveSecretKeyArgon2(password, Managed.GetDefaultArgon2Parameters());

            CollectionAssert.AreNotEqual(result1.SecretKey.ToByteArray(), result2.SecretKey.ToByteArray());
            CollectionAssert.AreNotEqual(result1.Parameters.ToByteArray(), result2.Parameters.ToByteArray());
        }

        [TestMethod]
        public void DeriveSecretKeyPbkdf2WithSalt_FixedSalt_ProducesSameKey()
        {
            byte[] password = "pbkdf2 test password"u8.ToArray();
            byte[] salt = "fixed_salt_16byt"u8.ToArray();

            KeyDerivationResult result1 = Managed.DeriveSecretKeyPbkdf2WithSalt(password, salt, 10);
            KeyDerivationResult result2 = Managed.DeriveSecretKeyPbkdf2WithSalt(password, salt, 10);

            // Same password + same salt + same iterations → same key and same parameters
            CollectionAssert.AreEqual(result1.SecretKey.ToByteArray(), result2.SecretKey.ToByteArray());
            CollectionAssert.AreEqual(result1.Parameters.ToByteArray(), result2.Parameters.ToByteArray());
        }

        [TestMethod]
        public void DeriveEncryptDecryptWithPassword_RoundTrip()
        {
            byte[] data = "Hello, derive-encrypt!"u8.ToArray();
            byte[] password = "s3cr3tPa$$w0rd"u8.ToArray();

            byte[] blob = Managed.DeriveEncryptWithPassword(data, password);
            Assert.IsNotNull(blob);
            Assert.IsTrue(Utils.ValidateHeader(blob, DataType.KdfEncryptedData));

            byte[]? decrypted = Managed.DeriveDecryptWithPassword(blob, password);
            Assert.IsNotNull(decrypted);
            CollectionAssert.AreEqual(data, decrypted);
        }

        [TestMethod]
        public void DeriveEncryptDecryptWithPassword_WithAad_RoundTrip()
        {
            byte[] data = "sensitive payload"u8.ToArray();
            byte[] password = "pa$$word"u8.ToArray();
            byte[] aad = "public context"u8.ToArray();
            byte[] wrongAad = "tampered context"u8.ToArray();

            byte[] blob = Managed.DeriveEncryptWithPassword(data, password, aad);
            Assert.IsNotNull(blob);

            byte[]? decrypted = Managed.DeriveDecryptWithPassword(blob, password, aad);
            Assert.IsNotNull(decrypted);
            CollectionAssert.AreEqual(data, decrypted);

            Assert.ThrowsException<DevolutionsCryptoException>(() => Managed.DeriveDecryptWithPassword(blob, password, wrongAad));
        }

        [TestMethod]
        public void DeriveEncryptDecryptWithPassword_WrongPassword_Throws()
        {
            byte[] data = "secret"u8.ToArray();
            byte[] password = "correct-password"u8.ToArray();
            byte[] wrongPassword = "wrong-password"u8.ToArray();

            byte[] blob = Managed.DeriveEncryptWithPassword(data, password);

            Assert.ThrowsException<DevolutionsCryptoException>(() => Managed.DeriveDecryptWithPassword(blob, wrongPassword));
        }

        [TestMethod]
        public void DeriveEncryptDecryptWithPassword_AesVersion_RoundTrip()
        {
            byte[] data = "AES-CBC encrypt test"u8.ToArray();
            byte[] password = "aes-password"u8.ToArray();

            byte[] blob = Managed.DeriveEncryptWithPassword(data, password, cipherTextVersion: CipherTextVersion.V1);
            Assert.IsNotNull(blob);

            byte[]? decrypted = Managed.DeriveDecryptWithPassword(blob, password);
            Assert.IsNotNull(decrypted);
            CollectionAssert.AreEqual(data, decrypted);
        }

        [TestMethod]
        public void DeriveEncryptDecryptWithPassword_WithDerivationParameters_RoundTrip()
        {
            byte[] data = "using pre-built params"u8.ToArray();
            byte[] password = "params-password"u8.ToArray();

            // Generate derivation parameters first, then reuse them
            KeyDerivationResult derivResult = Managed.DeriveSecretKeyArgon2(password, Managed.GetDefaultArgon2Parameters());
            DerivationParameters derivParams = derivResult.Parameters;

            byte[] blob = Managed.DeriveEncryptWithPassword(data, password, derivationParameters: derivParams);
            Assert.IsNotNull(blob);

            byte[]? decrypted = Managed.DeriveDecryptWithPassword(blob, password);
            Assert.IsNotNull(decrypted);
            CollectionAssert.AreEqual(data, decrypted);
        }

        [TestMethod]
        public void DeriveDecryptWithPassword_NullData_ReturnsNull()
        {
            byte[]? result = Managed.DeriveDecryptWithPassword(null, "password"u8.ToArray());
            Assert.IsNull(result);
        }

        private static byte[][] GetSharesKeys()
        {
            const int nbShares = 3;
            var shares = new byte[nbShares][];

            var array0 = new byte[] { 0x0d, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x01, 0x80, 0xa4, 0x08, 0x4a, 0xbb, 0xfb, 0x0e, 0x97, 0xdc, 0xa8 };
            shares[0] = array0;
            var array2 = new byte[] { 0x0d, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x03, 0xd6, 0xa9, 0x57, 0x9d, 0xda, 0xac, 0x41, 0x30, 0x57, 0x76 };
            shares[1] = array2;
            var array4 = new byte[] { 0x0d, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x05, 0xc3, 0x84, 0x27, 0x69, 0xe7, 0x13, 0xc0, 0x04, 0xec, 0x5c };
            shares[2] = array4;

            return shares;
        }

        private static byte[][] GetSharesKeys2()
        {
            const int nbShares = 3;
            var shares = new byte[nbShares][];

            var array1 = new byte[] { 0x0d, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x02, 0x84, 0x61, 0x49, 0x6a, 0xbe, 0xc8, 0xe2, 0xf5, 0x71, 0x30 };
            shares[0] = array1;
            var array2 = new byte[] { 0x0d, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x03, 0xd6, 0xa9, 0x57, 0x9d, 0xda, 0xac, 0x41, 0x30, 0x57, 0x76 };
            shares[1] = array2;
            var array3 = new byte[] { 0x0d, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x04, 0x91, 0x4c, 0x39, 0x9e, 0x83, 0x77, 0x63, 0xc1, 0xca, 0x1a };
            shares[2] = array3;

            return shares;
        }
    }
}
#pragma warning restore SA1600 // Elements should be documented