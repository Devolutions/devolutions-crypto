namespace Tests
{
    using Devolutions.Cryptography;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    /// <summary>
    ///
    /// </summary>
    [TestClass]
    public class TestManaged
    {
        private readonly byte[] _byteArray = new byte[] { 0x41, 0x42, 0x43 };
        private readonly string _textToTest = "ABC";
        private readonly string _textBase64ToTest = "QUJD";
        private readonly byte[] _cryptoKeyByteArray = new byte[] { 0x4b, 0x65, 0x79, 0x31, 0x32, 0x33 };
        private readonly string _cryptoKey = "Key123";

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void EncryptBase64WithPassword()
        {
            var b = Managed.EncryptBase64WithPassword(_textBase64ToTest, _cryptoKey);
            Assert.IsTrue(Utils.ValidateSignature(b, DataType.Cipher));
            var c = Managed.DecryptWithPassword(b, _cryptoKey);
            var d = Utils.ByteArrayToString(c);
            Assert.AreEqual(d, _textToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void EncryptBase64WithPasswordAsString()
        {
            var b = Managed.EncryptBase64WithPasswordAsString(_textBase64ToTest, _cryptoKey);
            var c = Managed.DecryptWithPasswordAsString(b, _cryptoKey);
            Assert.AreEqual(c, _textToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void EncryptWithKeyAsString_DecryptWithKeyAsString()
        {
            var x = Utils.StringToByteArray(_textToTest);
            var y = Utils.StringToByteArray(_cryptoKey);
            var b = Managed.EncryptWithKeyAsString(x, y, CipherVersion.Latest);
            var c = Managed.DecryptWithKeyAsString(b, y);
            Assert.AreEqual(c, _textToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void EncryptWithKey_DecryptWithKey()
        {
            var x = Utils.StringToByteArray(_textToTest);
            var y = Utils.StringToByteArray(_cryptoKey);
            var b = Managed.EncryptWithKey(x, y, CipherVersion.Latest);
            var c = Managed.DecryptWithKey(b, y);
            var d = Utils.ByteArrayToString(c);
            Assert.AreEqual(d, _textToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void EncryptWithPasswordAsString_And_DecryptWithPasswordAsString()
        {
            var x = Utils.StringToByteArray(_textBase64ToTest);
            var y = "pwd";
            var b = Managed.EncryptWithPasswordAsString(x, y, 100);
            var z = Managed.DecryptWithPasswordAsString(b, y, 100);
            Assert.AreEqual(z, _textBase64ToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void DecryptWithPassword()
        {
            const string x = "DQwCAAAAAgDsQkLRs1I3054gNOYP7ifVSpOMFEV8vTfoMuZOWAzbMR2b1QLyIe0/NFNKr8rniijd8PxHv29N";
            const string y = "testPa$$";
            var z = Managed.DecryptWithPassword(x, y);
            var b = Utils.ByteArrayToString(z);
            Assert.AreEqual(b, "test Ciph3rtext");
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void DecryptWithPassword2()
        {
            const string x = "DQwCAAAAAgDutPWBLPHG0+ocNw+Yzs6xygGOeOlNPOAjbYDdbJKjPRnEP8HuDN7Y3h3dCoH81Szf3tCf3mNf";
            const string y = "testPa$$";
            var z = Managed.DecryptWithPassword(x, y);
            var b = Utils.ByteArrayToString(z);
            Assert.AreEqual(b, "test Ciph3rtext");
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void EncryptWithPasswordAsString()
        {
            var x = Utils.StringToByteArray(_textToTest);
            var y = Managed.EncryptWithPasswordAsString(x, _cryptoKey);
            var z = Managed.DecryptWithPasswordAsString(y, _cryptoKey);
            Assert.AreEqual(z, _textToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void DecryptWithPasswordAsString()
        {
            var encryptedData = "DQwCAAAAAgCoE9Y3m06QaPSAiL2qegthcm0+zZWt4fXbdqcefkzD6y8pnWsMzLkx/32t";

            var y = Managed.DecryptWithPasswordAsString(encryptedData, _cryptoKey);
            Assert.AreEqual(y, _textToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void DecryptWithKey()
        {
            var encryptedData = new byte[]
            {
                0x0d, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0xa4, 0x24,
                0x87, 0x8e, 0xa2, 0xcb, 0xd9, 0x53, 0xc4, 0x14, 0xbf, 0x9d,
                0x56, 0x10, 0x53, 0x72, 0x75, 0xf3, 0x15, 0x2e, 0xfa, 0x55,
                0x2a, 0xda, 0xee,  0xe7, 0x7a, 0xfd, 0x1d, 0xf0, 0xe8, 0x97,
                0x0b, 0xc3, 0x63, 0x20, 0x07, 0x46, 0xaa, 0x14, 0x18, 0xd6,
                0xd1, 0x4d
            };

            var y = Managed.DecryptWithKey(encryptedData, _cryptoKeyByteArray);
            var z = Utils.ByteArrayToString(y);
            Assert.AreEqual(z, _textBase64ToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void DecryptWithKeyAsString()
        {
            var encryptedData = new byte[]
            {
                0x0d, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0xa4, 0x24,
                0x87, 0x8e, 0xa2, 0xcb, 0xd9, 0x53, 0xc4, 0x14, 0xbf, 0x9d,
                0x56, 0x10, 0x53, 0x72, 0x75, 0xf3, 0x15, 0x2e, 0xfa, 0x55,
                0x2a, 0xda, 0xee,  0xe7, 0x7a, 0xfd, 0x1d, 0xf0, 0xe8, 0x97,
                0x0b, 0xc3, 0x63, 0x20, 0x07, 0x46, 0xaa, 0x14, 0x18, 0xd6,
                0xd1, 0x4d
            };

            var y = Managed.DecryptWithKeyAsString(encryptedData, _cryptoKeyByteArray);
            Assert.AreEqual(y, _textBase64ToTest);
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
            var x = Utils.GetDecodedLength(_textBase64ToTest);
            Assert.AreEqual((int)x, 3);
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
            var x = Utils.Decode(_textBase64ToTest);
            CollectionAssert.AreEqual(x, _byteArray);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void Encode()
        {
            var x = Utils.Encode(_byteArray);
            Assert.AreEqual(x, _textBase64ToTest);
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
            Assert.AreEqual(x, _textBase64ToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void StringToByteArray()
        {
            var x = Utils.StringToByteArray(_textToTest);
            CollectionAssert.AreEqual(x, _byteArray);
        }
    }
}
