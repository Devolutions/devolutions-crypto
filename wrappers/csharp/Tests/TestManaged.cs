using Devolutions.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests
{
    /// <summary>
    ///
    /// </summary>
    [TestClass]
    public class TestManaged
    {
        private readonly byte[] _byteArray = new byte[] { 0x41, 0x42, 0x43 };
        private readonly string _textToTest = "QUJD";
        private readonly string _textBase64 = "UVVKRA==";

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void EncryptWithPasswordAsString_And_DecryptWithPasswordAsString()
        {
            var x = Utils.Decode(_textToTest);
            var y = "pwd";
            var b = Managed.EncryptWithPasswordAsString(x, y, 100);
            var z = Managed.DecryptWithPasswordAsString(b, y, 100);
            Assert.AreEqual(z, _textToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void DeriveKey()
        {
            var x = Utils.StringToByteArray("testpassword");
            var z = Managed.DeriveKey(x);
            var b = Utils.Encode(z);
            Assert.AreEqual(b, "ImfGCyv6PwMYaJShGxR4MfVrjuUrsI0CSarJgOApwf8=");
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void DeriveKey2()
        {
            var x = Utils.StringToByteArray("testPa$$");
            var z = Managed.DeriveKey(x, null, 100);
            var b = Utils.Encode(z);
            Assert.AreEqual(b, "ev/GiJLvOgIkkWrnIrHSi2fdZE5qJBIrW+DLeMLIXK4=");
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void DeriveKey3()
        {
            var x = Utils.StringToByteArray("testPa$$");
            var y = Utils.Decode("tdTt5wgeqQYLvkiXKkFirqy2hMbzadBtL+jekVeNCRA=");
            var z = Managed.DeriveKey(x, y, 100);
            var b = Utils.Encode(z);
            Assert.AreEqual(b, "ZaYRZeQiIPJ+Jl511AgHZjv4/HbCFq4eUP9yNa3gowI=");
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void Decode()
        {
            var x = Utils.Decode(_textToTest);
            CollectionAssert.AreEqual(x, _byteArray);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void Encode()
        {
            var x = Utils.Encode(_byteArray);
            Assert.AreEqual(x, _textToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void GetEncodedLength()
        {
            var x = Utils.GetEncodedLength(_byteArray);
            Assert.AreEqual((int)x, 4);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void GetDecodedLength()
        {
            var x = Utils.GetDecodedLength(_textToTest);
            Assert.AreEqual((int)x, 4);
        }

        /// <summary>
        /// Convert the Array bytes into UTF8 text
        /// </summary>
        [TestMethod]
        public void ByteArrayToString()
        {
            var x = Utils.ByteArrayToString(_byteArray);
            Assert.AreEqual(x, _textToTest);
        }

        /// <summary>
        /// Convert the Array bytes into string text
        /// </summary>
        [TestMethod]
        public void ToBase64String()
        {
            var x = Utils.ToBase64String(_byteArray);
            Assert.AreEqual(x, _textToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void StringToByteArray()
        {
            var x = Utils.Decode(_textToTest);
            CollectionAssert.AreEqual(x, _byteArray);
        }
    }
}
