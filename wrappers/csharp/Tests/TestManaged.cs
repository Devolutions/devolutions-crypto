using Devolutions.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests
{
    [TestClass]
    public class TestManaged
    {
        private readonly byte[] _byteArray = new byte[] { 0x41, 0x42, 0x43 };
        private readonly string _textToTest = "QUJD";
        private readonly string _textBase64 = "UVVKRA==";

        [TestMethod]
        public void DecryptWithPasswordAsString()
        {
            var x = Utils.StringToByteArray(_textToTest);
            var y = "pwd";
            var z = Managed.DecryptWithPasswordAsString(x, y, 100);
            Assert.AreEqual(z, _textToTest);
        }

        [TestMethod]
        public void DeriveKey()
        {
            var x = Utils.Base64StringToByteArray("testpassword");
            var z = Managed.DeriveKey(x);
            var b = Utils.ToBase64String(z);
            Assert.AreEqual(b, "Z8q3X96rLXK9jdrN1UgKHNA3dkWPopKsh03TsSND/Bg=");
        }

        [TestMethod]
        public void Decode()
        {
            var x = Utils.Decode(_textToTest);
            Assert.AreEqual(x, _byteArray);
        }

        [TestMethod]
        public void Encode()
        {
            var x = Utils.Encode(_byteArray);
            Assert.AreEqual(x, _textToTest);
        }

        [TestMethod]
        public void GetEncodedLength()
        {
            var x = Utils.GetEncodedLength(_byteArray);
            Assert.AreEqual((int)x, 4);
        }

        [TestMethod]
        public void GetDecodedLength()
        {
            var x = Utils.GetDecodedLength(_textToTest);
            Assert.AreEqual((int)x, 4);
        }

        [TestMethod]
        public void ByteArrayToString()
        {
            var x = Utils.ByteArrayToString(_byteArray);
            Assert.AreEqual(x, _textToTest);
        }

        [TestMethod]
        public void ToBase64String()
        {
            var x = Utils.ToBase64String(_byteArray);
            Assert.AreEqual(x, _textBase64);
        }

        [TestMethod]
        public void StringToByteArray()
        {
            var x = Utils.StringToByteArray(_textToTest);
            Assert.AreEqual(x, _byteArray);
        }
    }
}
