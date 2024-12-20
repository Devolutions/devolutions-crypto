#pragma warning disable SA1600 // Elements should be documented
namespace Devolutions.Crypto.Tests
{
    using System.IO;
    using Devolutions.Cryptography;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class TestStreams
    {
        [TestMethod]
        public void EncryptStream()
        {
            byte[] base64DataAsUtf8ByteArray = Utils.StringToUtf8ByteArray(TestData.Base64TestDataStream);

            byte[] header;

            using (MemoryStream ms = new MemoryStream())
            {
                using (EncryptionStream ec = new EncryptionStream(TestData.BytesTestKey, System.Array.Empty<byte>(), 1000, false, 0, ms))
                {
                    header = ec.GetHeader();

                    Assert.IsTrue(Utils.ValidateHeader(header, DataType.OnlineCiphertext));

                    using (StreamWriter writer = new StreamWriter(ec))
                    {
                        //writer.Write(new byte[3]);
                        writer.Write(base64DataAsUtf8ByteArray);
                    }
                }

                byte[] result = ms.ToArray();

                Assert.AreNotEqual(result, base64DataAsUtf8ByteArray);
                Assert.AreNotEqual(result, new byte[1000]);
            }
        }
    }
}