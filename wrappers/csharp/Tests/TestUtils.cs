using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Devolutions.Cryptography;

namespace Tests
{
    [TestClass]
    public class TestUtils
    {
        private readonly byte[] _byteArray = new byte[] {0x41, 0x42, 0x43};
        private readonly string _textToTest = "QUJD";
        private readonly string _cryptoKey = "Key123";

        [TestMethod]
        public void ToBase64String()
        {
            Assert.AreEqual(Utils.ToBase64String(_byteArray), _textToTest);
        }

        [TestMethod]
        public void StringToByteArray()
        {
            CollectionAssert.AreEqual(Utils.StringToByteArray(_textToTest), Encoding.UTF8.GetBytes(_textToTest));
        }

        [TestMethod]
        public void Base64StringToByteArray()
        {
            var x = Utils.Base64StringToByteArray(_textToTest);
            CollectionAssert.AreEqual(x, _byteArray);
        }

        [TestMethod]
        public void ByteArrayToString()
        {
            var x = Utils.StringToByteArray(_textToTest);
            var y = Utils.ByteArrayToString(x);
            Assert.AreEqual(y, _textToTest);
        }

        [TestMethod]
        public void GetEncodedLength()
        {
            var y = Utils.GetEncodedLength(_byteArray);
            Assert.AreEqual(4, y);
        }

        [TestMethod]
        public void GetDecodedLength()
        {
            var y = Utils.GetDecodedLength(_textToTest);
            Assert.AreEqual(3, y);
        }

        [TestMethod]
        public void Encode()
        {
            var y = Utils.Encode(_byteArray);
            Assert.AreEqual(y, _textToTest);
        }

        [TestMethod]
        public void Decode()
        {
            var x = Utils.Decode(_textToTest);
            CollectionAssert.AreEqual(x, _byteArray);
        }

        [TestMethod]
        public void ValidateSignature()
        {
            var textToEncrypt = Utils.StringToByteArray(_textToTest);
            var key = Utils.StringToByteArray(_cryptoKey);

            var encryptedWithDevo = Native.Encrypt(textToEncrypt, key);

            Assert.IsFalse(Utils.ValidateSignature(textToEncrypt, DataType.Cipher));
            Assert.IsTrue(Utils.ValidateSignature(encryptedWithDevo, DataType.Cipher));
        }
    }
}
