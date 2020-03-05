#if DOTNET_FRAMEWORK
namespace dotnet_framework
#endif
#if DOTNET_CORE
namespace dotnet_core
#endif
{
    using Devolutions.Cryptography;

    using Microsoft.VisualStudio.TestTools.UnitTesting;

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
            const string encrytedDataAsBase64 = "DQwCAAAAAgDsQkLRs1I3054gNOYP7ifVSpOMFEV8vTfoMuZOWAzbMR2b1QLyIe0/NFNKr8rniijd8PxHv29N";
            const string password = "testPa$$";
            byte[] decryptResult = Managed.DecryptWithPassword(encrytedDataAsBase64, password);
            string decryptResultString = Utils.ByteArrayToUtf8String(decryptResult);
            Assert.AreEqual(decryptResultString, "test Ciph3rtext");
        }

        [TestMethod]
        public void DecryptWithPassword2_5()
        {
            const string encrytedDataAsBase64 = "DQwCAAAAAgDutPWBLPHG0+ocNw+Yzs6xygGOeOlNPOAjbYDdbJKjPRnEP8HuDN7Y3h3dCoH81Szf3tCf3mNf";
            const string password = "testPa$$";
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
        public void DeriveKey()
        {
            byte[] encodedPassword = Utils.StringToUtf8ByteArray("testpassword");
            byte[] derivedPassword = Managed.DeriveKey(encodedPassword);
            string derivedPasswordAsBase64String = Utils.EncodeToBase64String(derivedPassword);
            Assert.AreEqual(derivedPasswordAsBase64String, "ImfGCyv6PwMYaJShGxR4MfVrjuUrsI0CSarJgOApwf8=");
        }

        [TestMethod]
        public void DeriveKey2()
        {
            byte[] encodedPassword = Utils.StringToUtf8ByteArray("testPa$$");
            byte[] derivedPassword = Managed.DeriveKey(encodedPassword, null, 100);
            string derivedPasswordAsBase64String = Utils.EncodeToBase64String(derivedPassword);
            Assert.AreEqual(derivedPasswordAsBase64String, "ev/GiJLvOgIkkWrnIrHSi2fdZE5qJBIrW+DLeMLIXK4=");
        }

        [TestMethod]
        public void DeriveKey3()
        {
            byte[] encodedPassword = Utils.StringToUtf8ByteArray("testPa$$");
            byte[] saltBytes = Utils.DecodeFromBase64("tdTt5wgeqQYLvkiXKkFirqy2hMbzadBtL+jekVeNCRA=");
            byte[] derivedPassword = Managed.DeriveKey(encodedPassword, saltBytes, 100);
            string derivedPasswordAsBase64String = Utils.EncodeToBase64String(derivedPassword);
            Assert.AreEqual(derivedPasswordAsBase64String, "ZaYRZeQiIPJ+Jl511AgHZjv4/HbCFq4eUP9yNa3gowI=");
        }

        [TestMethod]
        public void Encode()
        {
            string encodedArrayToBase64String = Utils.EncodeToBase64String(TestData.BytesTestData);
            Assert.AreEqual(encodedArrayToBase64String, TestData.Base64TestData);
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
        public void GetDecodedLength()
        {
            int bufferDecodedLength = Utils.GetDecodedLength(TestData.Base64TestData);
            Assert.AreEqual(bufferDecodedLength, 3);
        }

        [TestMethod]
        public void GetEncodedLength()
        {
            int stringEncodedLength = Utils.GetEncodedLength(TestData.BytesTestData);
            Assert.AreEqual(stringEncodedLength, 4);
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
    }
}