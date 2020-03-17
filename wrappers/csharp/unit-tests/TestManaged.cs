#pragma warning disable SA1600 // Elements should be documented

#if DOTNET_FRAMEWORK
#pragma warning disable SA1300 // Element should begin with upper-case letter
namespace dotnet_framework
#pragma warning restore SA1300 // Element should begin with upper-case letter
#endif
#if DOTNET_CORE
namespace dotnet_core
#endif
#if XAMARIN_MAC_FULL
namespace xamarin_mac_full
#endif
{
#if XAMARIN_MAC_FULL
    using NUnit.Framework;
    using TestClassAttribute = NUnit.Framework.TestFixtureAttribute;
    using TestMethodAttribute = NUnit.Framework.TestCaseAttribute;
#else
    using Microsoft.VisualStudio.TestTools.UnitTesting;
#endif
    using System;
    using System.Text;

    using Devolutions.Cryptography;
    using Devolutions.Cryptography.Argon2;

    [TestClass]
    public class TestManaged
    {
        [TestMethod]
        public void ByteArrayToString()
        {
            string conversionResult = Utils.ByteArrayToUtf8String(TestData.BytesTestData);
            Assert.AreEqual(conversionResult, TestData.StringTestData);
        }

        [TestMethod]
        public void Decode()
        {
            byte[] data = Utils.DecodeFromBase64(TestData.Base64TestData);
            CollectionAssert.AreEqual(data, TestData.BytesTestData);
        }

        [TestMethod]
        public void Decrypt()
        {
            byte[] decryptResult = Managed.Decrypt(TestData.EncryptedData, TestData.BytesTestKey);
            string encodedByteArrayToUtf8String = Utils.ByteArrayToUtf8String(decryptResult);
            Assert.AreEqual(encodedByteArrayToUtf8String, TestData.Base64TestData);
        }

        [TestMethod]
        public void DecryptAsymmetric_Test()
        {
            byte[] encryptedData = Convert.FromBase64String("DQwCAAIAAgD5rUXkPQO55rzI69WSxtVTA43lDXougn6BxJ7evqf+Yq+SEGXZxpE49874fz/aEk39LTnh1yWnY2VNoAAqKVB5CWZryd6SSld8Sx8v");

            byte[] decryptedData = Managed.DecryptAsymmetric(encryptedData, TestData.AlicePrivateKey);

            Assert.IsTrue(decryptedData != null);
            Assert.IsTrue(Encoding.UTF8.GetString(decryptedData) == "test");
        }

        [TestMethod]
        public void DecryptWithKey()
        {
            byte[] decryptResult = Managed.DecryptWithKey(TestData.EncryptedData, TestData.BytesTestKey);
            string decryptResultString = Utils.ByteArrayToUtf8String(decryptResult);
            Assert.AreEqual(decryptResultString, TestData.Base64TestData);
        }

        [TestMethod]
        public void DecryptWithKeyAsString()
        {
            string decryptResultString = Managed.DecryptWithKeyAsUtf8String(TestData.EncryptedData, TestData.BytesTestKey);
            Assert.AreEqual(decryptResultString, TestData.Base64TestData);
        }

        [TestMethod]
        public void DecryptWithPassword2()
        {
            string encrytedDataAsBase64 = "DQwCAAAAAgDsQkLRs1I3054gNOYP7ifVSpOMFEV8vTfoMuZOWAzbMR2b1QLyIe0/NFNKr8rniijd8PxHv29N";
            string password = "testPa$$";
            byte[] decryptResult = Managed.DecryptWithPassword(encrytedDataAsBase64, password);
            string decryptResultString = Utils.ByteArrayToUtf8String(decryptResult);
            Assert.AreEqual(decryptResultString, "test Ciph3rtext");
        }

        [TestMethod]
        public void DecryptWithPassword2_5()
        {
            string encrytedDataAsBase64 = "DQwCAAAAAgDutPWBLPHG0+ocNw+Yzs6xygGOeOlNPOAjbYDdbJKjPRnEP8HuDN7Y3h3dCoH81Szf3tCf3mNf";
            string password = "testPa$$";
            byte[] decryptResult = Managed.DecryptWithPassword(encrytedDataAsBase64, password);
            string decryptResultString = Utils.ByteArrayToUtf8String(decryptResult);
            Assert.AreEqual(decryptResultString, "test Ciph3rtext");
        }

        [TestMethod]
        public void DecryptWithPasswordAsString()
        {
            string encryptedDataAsBase64 = "DQwCAAAAAgCoE9Y3m06QaPSAiL2qegthcm0+zZWt4fXbdqcefkzD6y8pnWsMzLkx/32t";
            string decryptResultString = Managed.DecryptWithPasswordAsUtf8String(encryptedDataAsBase64, TestData.TestPassword);
            Assert.AreEqual(decryptResultString, TestData.StringTestData);
        }

        [TestMethod]
        public void DeriveKeyPair_Test()
        {
            KeyPair keyPair = Managed.DeriveKeyPair(new byte[] { 0, 1, 2, 3, 4, 5 }, Argon2Parameters.FromByteArray(Convert.FromBase64String(TestData.Argon2DefaultParametersb64)));

            Assert.IsTrue(keyPair != null);
            Assert.IsTrue(keyPair.PrivateKey != null);
            Assert.IsTrue(keyPair.PublicKey != null);

            Assert.IsTrue(keyPair.PrivateKeyString == "DQwBAAEAAQAgbzkrw3lP9KH/2MyTQlamDU39c5WziNWDZYMvqorEXw==");
            Assert.IsTrue(keyPair.PublicKeyString == "DQwBAAIAAQDY3Zz8t28PsxnT+CWk1Jftz5KTXnP6Tngjnaa+IZQ5Ug==");
        }

        [TestMethod]
        public void DerivePassword()
        {
            byte[] derivedPassword = Managed.DerivePassword(TestData.Base64TestData, null, 100);
            CollectionAssert.AreEqual(TestData.TestDeriveBytes, derivedPassword);
        }

        [TestMethod]
        public void Encode()
        {
            string encodedArrayToBase64String = Utils.EncodeToBase64String(TestData.BytesTestData);
            Assert.AreEqual(encodedArrayToBase64String, TestData.Base64TestData);
        }

        [TestMethod]
        public void Encrypt()
        {
            byte[] base64DataAsUtf8ByteArray = Utils.StringToUtf8ByteArray(TestData.Base64TestData2);
            byte[] encryptResult = Managed.Encrypt(base64DataAsUtf8ByteArray, TestData.BytesTestKey);
            Assert.IsTrue(Utils.ValidateSignature(encryptResult, DataType.Cipher));

            byte[] decryptResult = Managed.Decrypt(encryptResult, TestData.BytesTestKey);
            var decryptResultAsUtf8String = Utils.ByteArrayToUtf8String(decryptResult);
            Assert.AreEqual(decryptResultAsUtf8String, TestData.Base64TestData2);
        }

        [TestMethod]
        public void EncryptAsymmetric_Test()
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("test");

            byte[] encryptedData = Managed.EncryptAsymmetric(dataToEncrypt, TestData.AlicePublicKey);

            Assert.IsTrue(encryptedData != null);
            Assert.IsTrue(encryptedData.Length == 84);
        }

        [TestMethod]
        public void EncryptBase64WithPassword()
        {
            byte[] encryptedData = Managed.EncryptBase64WithPassword(TestData.Base64TestData, TestData.TestPassword);
            Assert.IsTrue(Utils.ValidateSignature(encryptedData, DataType.Cipher));
            byte[] decryptResult = Managed.DecryptWithPassword(encryptedData, TestData.TestPassword);
            string decryptResultString = Utils.ByteArrayToUtf8String(decryptResult);
            Assert.AreEqual(decryptResultString, TestData.StringTestData);
        }

        [TestMethod]
        public void EncryptBase64WithPasswordAsString()
        {
            string encryptResultString = Managed.EncryptBase64WithPasswordAsString(TestData.Base64TestData, TestData.TestPassword);
            string decryptResultAsUtf8String = Managed.DecryptWithPasswordAsUtf8String(encryptResultString, TestData.TestPassword);
            Assert.AreEqual(decryptResultAsUtf8String, TestData.StringTestData);
        }

        [TestMethod]
        public void EncryptWithKeyAsStringDecryptWithKeyAsString()
        {
            byte[] encodedData = Utils.StringToUtf8ByteArray(TestData.StringTestData);
            byte[] encodedPassword = Utils.StringToUtf8ByteArray(TestData.TestPassword);
            string encryptResultAsBase64String = Managed.EncryptWithKeyAsBase64String(encodedData, encodedPassword);
            string decryptResult = Managed.DecryptWithKeyAsUtf8String(encryptResultAsBase64String, encodedPassword);
            Assert.AreEqual(decryptResult, TestData.StringTestData);
        }

        [TestMethod]
        public void EncryptWithKeyDecryptWithKey()
        {
            byte[] encodedData = Utils.StringToUtf8ByteArray(TestData.StringTestData);
            byte[] encodedPassword = Utils.StringToUtf8ByteArray(TestData.TestPassword);
            byte[] encryptResultArray = Managed.EncryptWithKey(encodedData, encodedPassword);
            byte[] decryptResult = Managed.DecryptWithKey(encryptResultArray, encodedPassword);
            string decryptResultAsUtf8String = Utils.ByteArrayToUtf8String(decryptResult);
            Assert.AreEqual(decryptResultAsUtf8String, TestData.StringTestData);
        }

        [TestMethod]
        public void EncryptWithPasswordAsString()
        {
            byte[] encodedDataAsUtf8ByteArray = Utils.StringToUtf8ByteArray(TestData.StringTestData);
            string encryptResultAsBase64String = Managed.EncryptWithPasswordAsBase64String(encodedDataAsUtf8ByteArray, TestData.TestPassword);
            string decryptResultAsUtf8String = Managed.DecryptWithPasswordAsUtf8String(encryptResultAsBase64String, TestData.TestPassword);
            Assert.AreEqual(decryptResultAsUtf8String, TestData.StringTestData);
        }

        [TestMethod]
        public void EncryptWithPasswordAsStringAndDecryptWithPasswordAsString()
        {
            byte[] base64EncodedToUtf8ByteArray = Utils.StringToUtf8ByteArray(TestData.Base64TestData);
            string password = "pwd";
            string encryptResultAsBase64String = Managed.EncryptWithPasswordAsBase64String(base64EncodedToUtf8ByteArray, password, 100);
            string decryptionResultAsUtf8String = Managed.DecryptWithPasswordAsUtf8String(encryptResultAsBase64String, password, 100);
            Assert.AreEqual(decryptionResultAsUtf8String, TestData.Base64TestData);
        }

        [TestMethod]
        public void GenerateKey()
        {
            byte[] firstKey = Managed.GenerateKey(32);
            Assert.AreEqual(32, firstKey.Length);
            byte[] secondKey = Managed.GenerateKey(32);
            CollectionAssert.AreNotEqual(firstKey, secondKey);
        }

        [TestMethod]
        public void GenerateKeyPair()
        {
            KeyPair bob = Managed.GenerateKeyPair();
            KeyPair alice = Managed.GenerateKeyPair();
            byte[] bobMix = Managed.MixKeyExchange(bob.PrivateKey, alice.PublicKey);
            byte[] aliceMix = Managed.MixKeyExchange(alice.PrivateKey, bob.PublicKey);
            CollectionAssert.AreEqual(bobMix, aliceMix);
        }

        [TestMethod]
        public void GenerateSharedKey()
        {
            const int nbShares = 5;
            const int secretLength = 10;
            const int threshold = 3;
            var result = Managed.GenerateSharedKey(nbShares, threshold, secretLength);
            Assert.IsTrue(result != null && result.Length == 5 && result[0].Length == 20);
        }

        [TestMethod]
        public void GetDecodedLength()
        {
            int bufferDecodedLength = Utils.GetDecodedLength(TestData.Base64TestData);
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
            int stringEncodedLength = Utils.GetEncodedLength(TestData.BytesTestData);
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
            Assert.IsTrue(result != null && result.Length == 10);

            var shares2 = GetSharesKeys2();
            var result2 = Managed.JoinShares(shares);
            var val2 = Utils.ByteArrayToUtf8String(result);

            Assert.IsTrue(result != null && result.Length == 10);
            Assert.AreEqual(val, val2);
        }

        [TestMethod]
        public void MixKeyExchange()
        {
            byte[] bobMix = Managed.MixKeyExchange(TestData.BobPrivateKey, TestData.AlicePublicKey);
            byte[] aliceMix = Managed.MixKeyExchange(TestData.AlicePrivateKey, TestData.BobPublicKey);
            CollectionAssert.AreEqual(bobMix, aliceMix);
        }

        [TestMethod]
        public void StringToByteArray()
        {
            byte[] dataEncodedToUtf8ByteArray = Utils.StringToUtf8ByteArray(TestData.StringTestData);
            CollectionAssert.AreEqual(dataEncodedToUtf8ByteArray, TestData.BytesTestData);
        }

        [TestMethod]
        public void ToBase64String()
        {
            string dataEncodedToBase64String = Utils.EncodeToBase64String(TestData.BytesTestData);
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