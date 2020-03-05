#if DOTNET_FRAMEWORK
namespace dotnet_framework
#endif

#if DOTNET_CORE
namespace dotnet_core
#endif
{
    using Devolutions.Cryptography;

    using Microsoft.VisualStudio.TestTools.UnitTesting;

    /// <summary>
    ///
    /// </summary>
    [TestClass]
    public class TestUtils
    {
        private const string CryptoKey = "Key123";

        private const string Text = "ABC";

        private const string TextToTest = "QUJD";

        private readonly byte[] byteArray = new byte[] { 0x41, 0x42, 0x43 };

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void Base64StringToByteArray()
        {
            var x = Utils.Base64StringToByteArray(TextToTest);
            CollectionAssert.AreEqual(x, this.byteArray);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void ByteArrayToString()
        {
            var x = new byte[] { 0x51, 0x55, 0x4a, 0x44 };
            var y = Utils.ByteArrayToUtf8String(x);
            Assert.AreEqual(y, TextToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void Decode()
        {
            var x = Utils.DecodeFromBase64(TextToTest);
            CollectionAssert.AreEqual(x, this.byteArray);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void Encode()
        {
            var y = Utils.EncodeToBase64String(this.byteArray);
            Assert.AreEqual(y, TextToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void GetDecodedLength()
        {
            var y = Utils.GetDecodedLength(Text);
            Assert.AreEqual(2, y);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void GetEncodedLength()
        {
            var y = Utils.GetEncodedLength(this.byteArray);
            Assert.AreEqual(4, y);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void StringToByteArray()
        {
            var x = new byte[] { 0x51, 0x55, 0x4a, 0x44 };
            CollectionAssert.AreEqual(Utils.StringToUtf8ByteArray(TextToTest), x);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void ToBase64String()
        {
            Assert.AreEqual(Utils.EncodeToBase64String(this.byteArray), TextToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void ValidateSignature()
        {
            var textToEncrypt = Utils.StringToUtf8ByteArray(TextToTest);
            var key = Utils.StringToUtf8ByteArray(CryptoKey);

            var encryptedWithDevo = Native.Encrypt(textToEncrypt, key);

            Assert.IsFalse(Utils.ValidateSignature(textToEncrypt, DataType.Cipher));
            Assert.IsTrue(Utils.ValidateSignature(encryptedWithDevo, DataType.Cipher));
        }
    }
}