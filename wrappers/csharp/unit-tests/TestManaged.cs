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
    public class TestManaged
    {
        private const string CryptoKey = "Key123";

        private const string TextBase64ToTest = "QUJD";

        private const string TextToTest = "ABC";

        private readonly byte[] byteArray = new byte[] { 0x41, 0x42, 0x43 };

        private readonly byte[] cryptoKeyByteArray = new byte[] { 0x4b, 0x65, 0x79, 0x31, 0x32, 0x33 };

        /// <summary>
        /// Convert the Array bytes into UTF8 text
        /// </summary>
        [TestMethod]
        public void ByteArrayToString()
        {
            var x = Utils.ByteArrayToUtf8String(this.byteArray);
            Assert.AreEqual(x, TextToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void Decode()
        {
            var x = Utils.DecodeFromBase64(TextBase64ToTest);
            CollectionAssert.AreEqual(x, this.byteArray);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void DecryptWithKey()
        {
            var encryptedData = new byte[]
                {
                    0x0d,
                    0x0c,
                    0x02,
                    0x00,
                    0x00,
                    0x00,
                    0x02,
                    0x00,
                    0xa4,
                    0x24,
                    0x87,
                    0x8e,
                    0xa2,
                    0xcb,
                    0xd9,
                    0x53,
                    0xc4,
                    0x14,
                    0xbf,
                    0x9d,
                    0x56,
                    0x10,
                    0x53,
                    0x72,
                    0x75,
                    0xf3,
                    0x15,
                    0x2e,
                    0xfa,
                    0x55,
                    0x2a,
                    0xda,
                    0xee,
                    0xe7,
                    0x7a,
                    0xfd,
                    0x1d,
                    0xf0,
                    0xe8,
                    0x97,
                    0x0b,
                    0xc3,
                    0x63,
                    0x20,
                    0x07,
                    0x46,
                    0xaa,
                    0x14,
                    0x18,
                    0xd6,
                    0xd1,
                    0x4d
                };

            var y = Managed.DecryptWithKey(encryptedData, this.cryptoKeyByteArray);
            var z = Utils.ByteArrayToUtf8String(y);
            Assert.AreEqual(z, TextBase64ToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void DecryptWithKeyAsString()
        {
            var encryptedData = new byte[]
                {
                    0x0d,
                    0x0c,
                    0x02,
                    0x00,
                    0x00,
                    0x00,
                    0x02,
                    0x00,
                    0xa4,
                    0x24,
                    0x87,
                    0x8e,
                    0xa2,
                    0xcb,
                    0xd9,
                    0x53,
                    0xc4,
                    0x14,
                    0xbf,
                    0x9d,
                    0x56,
                    0x10,
                    0x53,
                    0x72,
                    0x75,
                    0xf3,
                    0x15,
                    0x2e,
                    0xfa,
                    0x55,
                    0x2a,
                    0xda,
                    0xee,
                    0xe7,
                    0x7a,
                    0xfd,
                    0x1d,
                    0xf0,
                    0xe8,
                    0x97,
                    0x0b,
                    0xc3,
                    0x63,
                    0x20,
                    0x07,
                    0x46,
                    0xaa,
                    0x14,
                    0x18,
                    0xd6,
                    0xd1,
                    0x4d
                };

            var y = Managed.DecryptWithKeyAsUtf8String(encryptedData, this.cryptoKeyByteArray);
            Assert.AreEqual(y, TextBase64ToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void DecryptWithPassword()
        {
            const string X = "DQwCAAAAAgDsQkLRs1I3054gNOYP7ifVSpOMFEV8vTfoMuZOWAzbMR2b1QLyIe0/NFNKr8rniijd8PxHv29N";
            const string Y = "testPa$$";
            var z = Managed.DecryptWithPassword(X, Y);
            var b = Utils.ByteArrayToUtf8String(z);
            Assert.AreEqual(b, "test Ciph3rtext");
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void DecryptWithPassword2()
        {
            const string X = "DQwCAAAAAgDutPWBLPHG0+ocNw+Yzs6xygGOeOlNPOAjbYDdbJKjPRnEP8HuDN7Y3h3dCoH81Szf3tCf3mNf";
            const string Y = "testPa$$";
            var z = Managed.DecryptWithPassword(X, Y);
            var b = Utils.ByteArrayToUtf8String(z);
            Assert.AreEqual(b, "test Ciph3rtext");
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void DecryptWithPasswordAsString()
        {
            var encryptedData = "DQwCAAAAAgCoE9Y3m06QaPSAiL2qegthcm0+zZWt4fXbdqcefkzD6y8pnWsMzLkx/32t";

            var y = Managed.DecryptWithPasswordAsUtf8String(encryptedData, CryptoKey);
            Assert.AreEqual(y, TextToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void DeriveKey()
        {
            var x = Utils.StringToUtf8ByteArray("testpassword");
            var z = Managed.DeriveKey(x);
            var b = Utils.EncodeToBase64String(z);
            Assert.AreEqual(b, "ImfGCyv6PwMYaJShGxR4MfVrjuUrsI0CSarJgOApwf8=");
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void DeriveKey2()
        {
            var x = Utils.StringToUtf8ByteArray("testPa$$");
            var z = Managed.DeriveKey(x, null, 100);
            var b = Utils.EncodeToBase64String(z);
            Assert.AreEqual(b, "ev/GiJLvOgIkkWrnIrHSi2fdZE5qJBIrW+DLeMLIXK4=");
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void DeriveKey3()
        {
            var x = Utils.StringToUtf8ByteArray("testPa$$");
            var y = Utils.DecodeFromBase64("tdTt5wgeqQYLvkiXKkFirqy2hMbzadBtL+jekVeNCRA=");
            var z = Managed.DeriveKey(x, y, 100);
            var b = Utils.EncodeToBase64String(z);
            Assert.AreEqual(b, "ZaYRZeQiIPJ+Jl511AgHZjv4/HbCFq4eUP9yNa3gowI=");
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void Encode()
        {
            var x = Utils.EncodeToBase64String(this.byteArray);
            Assert.AreEqual(x, TextBase64ToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void EncryptBase64WithPassword()
        {
            var b = Managed.EncryptBase64WithPassword(TextBase64ToTest, CryptoKey);
            Assert.IsTrue(Utils.ValidateSignature(b, DataType.Cipher));
            var c = Managed.DecryptWithPassword(b, CryptoKey);
            var d = Utils.ByteArrayToUtf8String(c);
            Assert.AreEqual(d, TextToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void EncryptBase64WithPasswordAsString()
        {
            var b = Managed.EncryptBase64WithPasswordAsString(TextBase64ToTest, CryptoKey);
            var c = Managed.DecryptWithPasswordAsUtf8String(b, CryptoKey);
            Assert.AreEqual(c, TextToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void EncryptWithKeyAsStringDecryptWithKeyAsString()
        {
            var x = Utils.StringToUtf8ByteArray(TextToTest);
            var y = Utils.StringToUtf8ByteArray(CryptoKey);
            var b = Managed.EncryptWithKeyAsBase64String(x, y, CipherVersion.Latest);
            var c = Managed.DecryptWithKeyAsUtf8String(b, y);
            Assert.AreEqual(c, TextToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void EncryptWithKeyDecryptWithKey()
        {
            var x = Utils.StringToUtf8ByteArray(TextToTest);
            var y = Utils.StringToUtf8ByteArray(CryptoKey);
            var b = Managed.EncryptWithKey(x, y, CipherVersion.Latest);
            var c = Managed.DecryptWithKey(b, y);
            var d = Utils.ByteArrayToUtf8String(c);
            Assert.AreEqual(d, TextToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void EncryptWithPasswordAsString()
        {
            var x = Utils.StringToUtf8ByteArray(TextToTest);
            var y = Managed.EncryptWithPasswordAsBase64String(x, CryptoKey);
            var z = Managed.DecryptWithPasswordAsUtf8String(y, CryptoKey);
            Assert.AreEqual(z, TextToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void EncryptWithPasswordAsStringAndDecryptWithPasswordAsString()
        {
            var x = Utils.StringToUtf8ByteArray(TextBase64ToTest);
            var y = "pwd";
            var b = Managed.EncryptWithPasswordAsBase64String(x, y, 100);
            var z = Managed.DecryptWithPasswordAsUtf8String(b, y, 100);
            Assert.AreEqual(z, TextBase64ToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void GetDecodedLength()
        {
            var x = Utils.GetDecodedLength(TextBase64ToTest);
            Assert.AreEqual((int)x, 3);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void GetEncodedLength()
        {
            var x = Utils.GetEncodedLength(this.byteArray);
            Assert.AreEqual((int)x, 4);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void StringToByteArray()
        {
            var x = Utils.StringToUtf8ByteArray(TextToTest);
            CollectionAssert.AreEqual(x, this.byteArray);
        }

        /// <summary>
        /// Convert the Array bytes into string text
        /// </summary>
        [TestMethod]
        public void ToBase64String()
        {
            var x = Utils.EncodeToBase64String(this.byteArray);
            Assert.AreEqual(x, TextBase64ToTest);
        }
    }
}