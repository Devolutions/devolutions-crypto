#if DOTNET_FRAMEWORK
namespace dotnet_framework
#endif

#if DOTNET_CORE
namespace dotnet_core
#endif
{
    using System;
    using System.Reflection;

    using Devolutions.Cryptography;

    using Microsoft.VisualStudio.TestTools.UnitTesting;

    /// <summary>
    ///
    /// </summary>
    [TestClass]
    public class TestNative
    {
        private const string TextToTest = "QUJD";

        private const string TextToTest2 = "QUJDDE";

        private readonly byte[] byteArray = new byte[] { 0x41, 0x42, 0x43 };

        private readonly byte[] cryptoKeyByteArray = new byte[] { 0x4b, 0x65, 0x79, 0x31, 0x32, 0x33 };

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void DecodeNative()
        {
            var x = Native.DecodeNative(TextToTest, (UIntPtr)TextToTest.Length, new byte[] { 0x00, 0x00, 0x00 }, (UIntPtr)0x00000003);
            Assert.AreEqual((long)0x0000000000000003, x);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void Decrypt()
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

            var y = Native.Decrypt(encryptedData, this.cryptoKeyByteArray);
            var z = Utils.ByteArrayToUtf8String(y);
            Assert.AreEqual(z, TextToTest);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void Decrypt2()
        {
            var encryptedData = Utils.Base64StringToByteArray(
                "DQwCAAAAAQCK1twEut+TeJfFbTWCRgHjyS6bOPOZUEQAeBtSFFRl2jHggM/34n68zIZWGbsZHkufVzU6mTN5N2Dx9bTplrycv5eNVevT4P9FdVHJ751D+A==");
            var encryptKey = Utils.Base64StringToByteArray("ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=");

            var y = Native.Decrypt(encryptedData, encryptKey);
            var z = Utils.ByteArrayToUtf8String(y);
            Assert.AreEqual(z, "test Ciph3rtext~");
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void Decrypt3()
        {
            var encryptedData = Utils.Base64StringToByteArray("DQwCAAAAAgAA0iPpI4IEzcrWAQiy6tqDqLbRYduGvlMC32mVH7tpIN2CXDUu5QHF91I7pMrmjt/61pm5CeR/IcU=");
            var encryptKey = Utils.Base64StringToByteArray("ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=");

            var y = Native.Decrypt(encryptedData, encryptKey);
            var z = Utils.ByteArrayToUtf8String(y);
            Assert.AreEqual(z, "test Ciph3rtext~2");
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void DeriveKey()
        {
            var derivedKey = new byte[]
                {
                    0xb8,
                    0xe8,
                    0xea,
                    0x5f,
                    0xe4,
                    0x90,
                    0x86,
                    0x28,
                    0x8d,
                    0x98,
                    0x67,
                    0x6c,
                    0xce,
                    0x9d,
                    0xd4,
                    0x21,
                    0x2c,
                    0x5a,
                    0xd0,
                    0x9b,
                    0x05,
                    0x89,
                    0xb3,
                    0x2f,
                    0xd8,
                    0x29,
                    0x7a,
                    0xc0,
                    0x67,
                    0xb7,
                    0xf3,
                    0xe2
                };
            var x = Native.DeriveKey(this.cryptoKeyByteArray, null, 100);

            CollectionAssert.AreEqual(derivedKey, x);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void DerivePassword()
        {
            var derivedPassword = new byte[]
                {
                    0x4d,
                    0x42,
                    0x5d,
                    0x3b,
                    0x8f,
                    0x36,
                    0xe4,
                    0xff,
                    0xb2,
                    0x56,
                    0xa4,
                    0xdc,
                    0x7c,
                    0x48,
                    0x66,
                    0x17,
                    0x7e,
                    0x74,
                    0x87,
                    0x61,
                    0x62,
                    0x68,
                    0xb1,
                    0x2b,
                    0x54,
                    0x0e,
                    0x1a,
                    0xf8,
                    0x03,
                    0xbb,
                    0x39,
                    0xc4
                };
            var y = Native.DerivePassword(TextToTest, null, 100);

            CollectionAssert.AreEqual(derivedPassword, y);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void EncodeNative()
        {
            var buffer = new byte[] { 0x51, 0x55, 0x4a, 0x44 };
            var x = Native.EncodeNative(this.byteArray, (UIntPtr)this.byteArray.Length, buffer, (UIntPtr)buffer.Length);
            Assert.AreEqual((long)0x0000000000000004, x);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void Encrypt()
        {
            var a = Utils.StringToUtf8ByteArray(TextToTest2);
            var x = Native.Encrypt(a, this.cryptoKeyByteArray);
            Assert.IsTrue(Utils.ValidateSignature(x, DataType.Cipher));

            var y = Native.Decrypt(x, this.cryptoKeyByteArray);
            var z = Utils.ByteArrayToUtf8String(y);
            Assert.AreEqual(z, TextToTest2);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void GenerateKey()
        {
            var y = Native.GenerateKey(32);
            Assert.AreEqual(32, y.Length);
            var z = Native.GenerateKey(32);
            CollectionAssert.AreNotEqual(y, z);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void GenerateKeyExchange()
        {
            var bob = Native.GenerateKeyExchange();
            var alice = Native.GenerateKeyExchange();
            var mixXKey = Native.MixKeyExchange(bob.PrivateKey, alice.PublicKey);
            var mixYKey = Native.MixKeyExchange(alice.PrivateKey, bob.PublicKey);
            CollectionAssert.AreEqual(mixYKey, mixXKey);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void HashPassword()
        {
            var y = Native.HashPassword(this.cryptoKeyByteArray);
            var z = Native.HashPassword(this.byteArray);

            Assert.IsTrue(Native.VerifyPassword(this.cryptoKeyByteArray, y));
            Assert.IsFalse(Native.VerifyPassword(z, y));
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void MixKeyExchange()
        {
            var bobPrivateKey = new byte[]
                {
                    0x0d,
                    0x0c,
                    0x01,
                    0x00,
                    0x01,
                    0x00,
                    0x01,
                    0x00,
                    0x50,
                    0xd6,
                    0x53,
                    0x23,
                    0x12,
                    0xcd,
                    0xfd,
                    0xa3,
                    0xa7,
                    0x4c,
                    0xac,
                    0x56,
                    0xcd,
                    0xe3,
                    0x7a,
                    0x69,
                    0x40,
                    0x1a,
                    0xe4,
                    0xd1,
                    0x5f,
                    0x55,
                    0xbd,
                    0x1f,
                    0xaa,
                    0x4a,
                    0xa8,
                    0x76,
                    0x30,
                    0x37,
                    0xf2,
                    0x49
                };
            var bobPublicKey = new byte[]
                {
                    0x0d,
                    0x0c,
                    0x01,
                    0x00,
                    0x02,
                    0x00,
                    0x01,
                    0x00,
                    0x39,
                    0x04,
                    0x34,
                    0x68,
                    0xf8,
                    0x08,
                    0xfd,
                    0xdc,
                    0xe0,
                    0xe4,
                    0xd2,
                    0x3e,
                    0x2c,
                    0x60,
                    0x9b,
                    0x23,
                    0xab,
                    0xf1,
                    0x49,
                    0xf5,
                    0xaf,
                    0x1d,
                    0x4c,
                    0x14,
                    0xdd,
                    0x03,
                    0x81,
                    0xe1,
                    0x10,
                    0x5d,
                    0x1e,
                    0x39,
                };

            var alicePrivateKey = new byte[]
                {
                    0x0d,
                    0x0c,
                    0x01,
                    0x00,
                    0x01,
                    0x00,
                    0x01,
                    0x00,
                    0x70,
                    0x89,
                    0x41,
                    0x7d,
                    0x2b,
                    0x5a,
                    0x0f,
                    0x02,
                    0x4e,
                    0xfb,
                    0x1f,
                    0x3c,
                    0x7a,
                    0x42,
                    0x08,
                    0xfa,
                    0x4a,
                    0x57,
                    0xa5,
                    0xda,
                    0xa8,
                    0xf9,
                    0x47,
                    0xdb,
                    0xd8,
                    0x40,
                    0x54,
                    0x8b,
                    0x49,
                    0xd6,
                    0xe1,
                    0x7a,
                };

            var alicePublicKey = new byte[]
                {
                    0x0d,
                    0x0c,
                    0x01,
                    0x00,
                    0x02,
                    0x00,
                    0x01,
                    0x00,
                    0x86,
                    0xef,
                    0x7b,
                    0x5f,
                    0x62,
                    0x12,
                    0xa0,
                    0x39,
                    0xa4,
                    0x4d,
                    0x17,
                    0xd8,
                    0x04,
                    0x1a,
                    0x70,
                    0x0a,
                    0xa9,
                    0x0f,
                    0xe3,
                    0xee,
                    0x7f,
                    0x90,
                    0x28,
                    0x0a,
                    0xe8,
                    0x11,
                    0x2b,
                    0x16,
                    0xb5,
                    0xd2,
                    0xd6,
                    0x77,
                };

            var mixXKey = Native.MixKeyExchange(bobPrivateKey, alicePublicKey);
            var mixYKey = Native.MixKeyExchange(alicePrivateKey, bobPublicKey);
            CollectionAssert.AreEqual(mixYKey, mixXKey);
        }

        /// <summary>
        ///
        /// </summary>
        [TestMethod]
        public void VerifyPassword()
        {
            var encryptedData = new byte[]
                {
                    0x0d,
                    0x0c,
                    0x03,
                    0x00,
                    0x00,
                    0x00,
                    0x01,
                    0x00,
                    0x10,
                    0x27,
                    0x00,
                    0x00,
                    0x36,
                    0xf8,
                    0x52,
                    0x24,
                    0x7a,
                    0x19,
                    0x10,
                    0xc5,
                    0xa4,
                    0x9c,
                    0x73,
                    0xec,
                    0x83,
                    0x58,
                    0x9b,
                    0xea,
                    0x63,
                    0x3a,
                    0xf1,
                    0xbf,
                    0xf6,
                    0xa4,
                    0xd8,
                    0xe0,
                    0x85,
                    0xc9,
                    0xaa,
                    0x9e,
                    0xe1,
                    0xef,
                    0x7f,
                    0x60,
                    0xf3,
                    0x3f,
                    0x1b,
                    0x6c,
                    0x5f,
                    0xce,
                    0x54,
                    0x55,
                    0xb8,
                    0x73,
                    0xc9,
                    0xd9,
                    0x22,
                    0xa0,
                    0x24,
                    0xca,
                    0xe8,
                    0xc9,
                    0x57,
                    0x96,
                    0x1b,
                    0x3d,
                    0xce,
                    0x47,
                    0xe5,
                    0xc3,
                    0x39,
                    0xe1,
                    0x0d,
                    0x08,
                    0x42,
                    0x70
                };
            Assert.IsTrue(Native.VerifyPassword(this.cryptoKeyByteArray, encryptedData));
        }

        public void VersionNative()
        {
            var assembly = Assembly.GetAssembly(typeof(Devolutions.Cryptography.Managed));
            var managedVersion = assembly.GetName().Version.ToString();

            var bufferSize = Native.VersionSizeNative();
            var buffer = new byte[bufferSize];
            Native.VersionNative(buffer, (UIntPtr)bufferSize);
            var nativeVersion = Utils.ByteArrayToUtf8String(buffer) + ".0";
            Assert.AreEqual(nativeVersion, managedVersion);
        }
    }
}