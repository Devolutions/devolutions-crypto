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
        public void DecryptAsymmetric_Test()
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
        public void DecryptWithPassword2()
        {
            string encryptedDataAsBase64 = "DQwCAAAAAgDsQkLRs1I3054gNOYP7ifVSpOMFEV8vTfoMuZOWAzbMR2b1QLyIe0/NFNKr8rniijd8PxHv29N";
            string password = "testPa$$";
            byte[]? decryptResult = Managed.DecryptWithPassword(encryptedDataAsBase64, password);
            string? decryptResultString = Utils.ByteArrayToUtf8String(decryptResult);
            Assert.AreEqual(decryptResultString, "test Ciph3rtext");
        }

        [TestMethod]
        public void DecryptWithPassword2_5()
        {
            try
            {
                string encryptedDataAsBase64 = "DQwCAAAAAgDutPWBLPHG0+ocNw+Yzs6xygGOeOlNPOAjbYDdbJKjPRnEP8HuDN7Y3h3dCoH81Szf3tCf3mNf";
                string password = "testPa$$";
                byte[]? decryptResult = Managed.DecryptWithPassword(encryptedDataAsBase64, password);
                string? decryptResultString = Utils.ByteArrayToUtf8String(decryptResult);
                Assert.AreEqual(decryptResultString, "test Ciph3rtext");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.InnerException?.Message);
                Console.WriteLine(ex.InnerException?.StackTrace);
            }
        }

        [TestMethod]
        public void DecryptWithPasswordAsUtf8String()
        {
            string encryptedDataAsBase64 = "DQwCAAAAAgCoE9Y3m06QaPSAiL2qegthcm0+zZWt4fXbdqcefkzD6y8pnWsMzLkx/32t";
            string? decryptResultString = Managed.DecryptWithPasswordAsUtf8String(encryptedDataAsBase64, TestData.TestPassword);
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
        public void EncryptAsymmetric_Test()
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("test");
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
            Assert.AreEqual(Convert.ToBase64String(signature), TestData.SignedTestingb64);
        }

        [TestMethod]
        public void VerifySignature()
        {
            byte[] signature = Convert.FromBase64String(TestData.SignedTestingb64);

            SigningKeyPair keypair = SigningKeyPair.FromByteArray(Convert.FromBase64String(TestData.SigningKeyPairb64));
            SigningPublicKey pubkey = SigningPublicKey.FromByteArray(Convert.FromBase64String(TestData.SigningPublicKeyb64));

            bool res = Managed.VerifySignature(Encoding.UTF8.GetBytes(TestData.SignTesting), pubkey, signature);

            Assert.AreEqual(res, true);
        }

        [TestMethod]
        public void VerifySignature_FailBadData()
        {
            byte[] signature = Convert.FromBase64String(TestData.SignedTestingb64);

            SigningKeyPair keypair = SigningKeyPair.FromByteArray(Convert.FromBase64String(TestData.SigningKeyPairb64));
            SigningPublicKey pubkey = SigningPublicKey.FromByteArray(Convert.FromBase64String(TestData.SigningPublicKeyb64));

            bool res = Managed.VerifySignature(Encoding.UTF8.GetBytes("bad data"), pubkey, signature);

            Assert.AreEqual(res, false);
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

            Assert.AreEqual(res, false);
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