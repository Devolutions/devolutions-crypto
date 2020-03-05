#if DOTNET_FRAMEWORK
namespace dotnet_framework
#endif
#if DOTNET_CORE
namespace dotnet_core
#endif
{
    using System;

    using Devolutions.Cryptography;

    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class TestNative
    {
        [TestMethod]
        public void DecodeNative()
        {
            long resultCode = Native.DecodeNative(TestData.Base64TestData, (UIntPtr)TestData.Base64TestData.Length, new byte[] { 0x00, 0x00, 0x00 }, (UIntPtr)0x00000003);
            Assert.AreEqual((long)0x0000000000000003, resultCode);
        }

        [TestMethod]
        public void Decrypt()
        {
            byte[] decryptResult = Native.Decrypt(TestData.EncryptedData, TestData.BytesTestKey);
            string encodedByteArrayToUtf8String = Utils.ByteArrayToUtf8String(decryptResult);
            Assert.AreEqual(encodedByteArrayToUtf8String, TestData.Base64TestData);
        }

        [TestMethod]
        public void Decrypt1()
        {
            byte[] encryptedData = Utils.Base64StringToByteArray(
                "DQwCAAAAAQCK1twEut+TeJfFbTWCRgHjyS6bOPOZUEQAeBtSFFRl2jHggM/34n68zIZWGbsZHkufVzU6mTN5N2Dx9bTplrycv5eNVevT4P9FdVHJ751D+A==");
            byte[] encryptKey = Utils.Base64StringToByteArray("ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=");

            byte[] decryptResult = Native.Decrypt(encryptedData, encryptKey);
            string decryptResultAsUtf8String = Utils.ByteArrayToUtf8String(decryptResult);
            Assert.AreEqual(decryptResultAsUtf8String, "test Ciph3rtext~");
        }

        [TestMethod]
        public void Decrypt2()
        {
            byte[] encryptedData = Utils.Base64StringToByteArray("DQwCAAAAAgAA0iPpI4IEzcrWAQiy6tqDqLbRYduGvlMC32mVH7tpIN2CXDUu5QHF91I7pMrmjt/61pm5CeR/IcU=");
            byte[] encryptKey = Utils.Base64StringToByteArray("ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=");

            byte[] decryptResult = Native.Decrypt(encryptedData, encryptKey);
            string decryptResultAsUtf8String = Utils.ByteArrayToUtf8String(decryptResult);
            Assert.AreEqual(decryptResultAsUtf8String, "test Ciph3rtext~2");
        }

        [TestMethod]
        public void DeriveKey()
        {
            byte[] derivedKey = Native.DeriveKey(TestData.BytesTestKey, null, 100);

            CollectionAssert.AreEqual(TestData.TestDeriveBytes2, derivedKey);
        }

        [TestMethod]
        public void DerivePassword()
        {
            byte[] derivedPassword = Native.DerivePassword(TestData.Base64TestData, null, 100);
            CollectionAssert.AreEqual(TestData.TestDeriveBytes, derivedPassword);
        }

        [TestMethod]
        public void EncodeNative()
        {
            byte[] buffer = new byte[] { 0x51, 0x55, 0x4a, 0x44 };
            long resultCode = Native.EncodeNative(TestData.BytesTestData, (UIntPtr)TestData.BytesTestData.Length, buffer, (UIntPtr)buffer.Length);
            Assert.AreEqual((long)0x0000000000000004, resultCode);
        }

        [TestMethod]
        public void Encrypt()
        {
            byte[] base64DataAsUtf8ByteArray = Utils.StringToUtf8ByteArray(TestData.Base64TestData2);
            byte[] encryptResult = Native.Encrypt(base64DataAsUtf8ByteArray, TestData.BytesTestKey);
            Assert.IsTrue(Utils.ValidateSignature(encryptResult, DataType.Cipher));

            byte[] decryptResult = Native.Decrypt(encryptResult, TestData.BytesTestKey);
            var decryptResultAsUtf8String = Utils.ByteArrayToUtf8String(decryptResult);
            Assert.AreEqual(decryptResultAsUtf8String, TestData.Base64TestData2);
        }

        [TestMethod]
        public void GenerateKey()
        {
            byte[] firstKey = Native.GenerateKey(32);
            Assert.AreEqual(32, firstKey.Length);
            byte[] secondKey = Native.GenerateKey(32);
            CollectionAssert.AreNotEqual(firstKey, secondKey);
        }

        [TestMethod]
        public void GenerateKeyExchange()
        {
            KeyExchange bob = Native.GenerateKeyExchange();
            KeyExchange alice = Native.GenerateKeyExchange();
            byte[] bobMix = Native.MixKeyExchange(bob.PrivateKey, alice.PublicKey);
            byte[] aliceMix = Native.MixKeyExchange(alice.PrivateKey, bob.PublicKey);
            CollectionAssert.AreEqual(bobMix, aliceMix);
        }

        [TestMethod]
        public void HashPassword()
        {
            byte[] firstHash = Native.HashPassword(TestData.BytesTestKey);
            byte[] secondHash = Native.HashPassword(TestData.BytesTestData);

            Assert.IsTrue(Native.VerifyPassword(TestData.BytesTestKey, firstHash));
            Assert.IsFalse(Native.VerifyPassword(secondHash, firstHash));
        }

        [TestMethod]
        public void MixKeyExchange()
        {
            byte[] bobMix = Native.MixKeyExchange(TestData.BobPrivateKey, TestData.AlicePublicKey);
            byte[] aliceMix = Native.MixKeyExchange(TestData.AlicePrivateKey, TestData.BobPublicKey);
            CollectionAssert.AreEqual(bobMix, aliceMix);
        }

        [TestMethod]
        public void VerifyPassword()
        {
            Assert.IsTrue(Native.VerifyPassword(TestData.BytesTestKey, TestData.TestHash));
        }
    }
}