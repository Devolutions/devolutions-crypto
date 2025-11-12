#pragma warning disable SA1600 // Elements should be documented
namespace Devolutions.Crypto.Tests
{
    using System;
    using System.IO;
    using Devolutions.Cryptography;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class TestStreams
    {
        [TestMethod]
        public void EncryptStream()
        {
            byte[] base64DataAsUtf8ByteArray = Utils.Base64StringToByteArray(TestData.Base64TestDataStream)!;

            using MemoryStream ms = new MemoryStream();
            using (EncryptionStream ec = new EncryptionStream(TestData.BytesTestKey, [], 1000, false, 0, ms))
            {
                byte[] header = ec.GetHeader();

                Assert.IsTrue(Utils.ValidateHeader(header, DataType.OnlineCiphertext));

                ec.Write(base64DataAsUtf8ByteArray, 0, base64DataAsUtf8ByteArray.Length);
                ec.FlushFinalBlock();
            }

            byte[] result = ms.ToArray();

            Assert.AreNotEqual(result, base64DataAsUtf8ByteArray);
            Assert.AreNotEqual(result, new byte[1000]);
            Assert.IsTrue(result.Length == 1721);
        }

        [TestMethod]
        public void DecryptStream()
        {
            byte[] base64DataAsUtf8ByteArray = Utils.Base64StringToByteArray(TestData.Base64TestDataStreamEncrypted)!;

            using MemoryStream ms = new MemoryStream();

            byte[] header = Utils.Base64StringToByteArray(TestData.Base64HeaderDataStreamEncrypted)!;
            using (DecryptionStream ec =
                   new DecryptionStream(TestData.BytesTestKey, [], header, false, ms, false))
            {
                Assert.IsTrue(Utils.ValidateHeader(header, DataType.OnlineCiphertext));

                ec.Write(base64DataAsUtf8ByteArray, 0, base64DataAsUtf8ByteArray.Length);
                ec.FlushFinalBlock();
            }

            byte[] result = ms.ToArray();

            Assert.AreNotEqual(result, base64DataAsUtf8ByteArray);
            Assert.AreNotEqual(result, new byte[1000]);
            Assert.IsTrue(result.Length == 1689);
            Assert.IsTrue(Utils.EncodeToBase64String(result) == TestData.Base64TestDataStream);
        }
    }
}