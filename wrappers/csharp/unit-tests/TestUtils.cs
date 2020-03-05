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
    public class TestUtils
    {
        [TestMethod]
        public void Base64StringToByteArray()
        {
            byte[] data = Utils.Base64StringToByteArray(TestData.Base64TestData);
            CollectionAssert.AreEqual(data, TestData.BytesTestData);
        }

        [TestMethod]
        public void ByteArrayToString()
        {
            byte[] data = new byte[] { 0x51, 0x55, 0x4a, 0x44 };
            string dataToUtf8String = Utils.ByteArrayToUtf8String(data);
            Assert.AreEqual(dataToUtf8String, TestData.Base64TestData);
        }

        [TestMethod]
        public void Decode()
        {
            byte[] decodedData = Utils.DecodeFromBase64(TestData.Base64TestData);
            CollectionAssert.AreEqual(decodedData, TestData.BytesTestData);
        }

        [TestMethod]
        public void Encode()
        {
            var y = Utils.EncodeToBase64String(TestData.BytesTestData);
            Assert.AreEqual(y, TestData.Base64TestData);
        }

        [TestMethod]
        public void GetDecodedLength()
        {
            int decodedLength = Utils.GetDecodedLength(TestData.StringTestData);
            Assert.AreEqual(2, decodedLength);
        }

        [TestMethod]
        public void GetEncodedLength()
        {
            int encodedLength = Utils.GetEncodedLength(TestData.BytesTestData);
            Assert.AreEqual(4, encodedLength);
        }

        [TestMethod]
        public void StringToByteArray()
        {
            byte[] data = new byte[] { 0x51, 0x55, 0x4a, 0x44 };
            CollectionAssert.AreEqual(Utils.StringToUtf8ByteArray(TestData.Base64TestData), data);
        }

        [TestMethod]
        public void ToBase64String()
        {
            Assert.AreEqual(Utils.EncodeToBase64String(TestData.BytesTestData), TestData.Base64TestData);
        }

        [TestMethod]
        public void ValidateSignature()
        {
            byte[] dataToEncrypt = Utils.StringToUtf8ByteArray(TestData.Base64TestData);
            byte[] password = Utils.StringToUtf8ByteArray(TestData.TestPassword);

            byte[] encryptResult = Native.Encrypt(dataToEncrypt, password);

            Assert.IsFalse(Utils.ValidateSignature(dataToEncrypt, DataType.Cipher));
            Assert.IsTrue(Utils.ValidateSignature(encryptResult, DataType.Cipher));
        }
    }
}