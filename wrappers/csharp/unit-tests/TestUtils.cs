#if DOTNET_FRAMEWORK
namespace dotnet_framework
#endif
#if DOTNET_CORE
namespace dotnet_core
#endif
#if XAMARIN_MAC_FULL
namespace xamarin_mac_full
#endif
{
    using System.IO;

    using Devolutions.Cryptography;

#if XAMARIN_MAC_FULL
    using NUnit.Framework;
    using TestClassAttribute = NUnit.Framework.TestFixtureAttribute;
    using TestMethodAttribute = NUnit.Framework.TestCaseAttribute;
#else
    using Microsoft.VisualStudio.TestTools.UnitTesting;
#endif

    [TestClass]
    public class TestUtils
    {
        [TestMethod]
        public void Base64StringToByteArray()
        {
            byte[] data = Utils.Base64StringToByteArray(TestData.Base64TestData);
            CollectionAssert.AreEqual(data, TestData.BytesTestData);
        }

        [TestMethod]
        public void ByteArrayToString()
        {
            byte[] data = new byte[] { 0x51, 0x55, 0x4a, 0x44 };
            string dataToUtf8String = Utils.ByteArrayToUtf8String(data);
            Assert.AreEqual(dataToUtf8String, TestData.Base64TestData);
        }

        [TestMethod]
        public void Decode()
        {
            byte[] decodedData = Utils.DecodeFromBase64(TestData.Base64TestData);
            CollectionAssert.AreEqual(decodedData, TestData.BytesTestData);
        }

        [TestMethod]
        public void Encode()
        {
            var y = Utils.EncodeToBase64String(TestData.BytesTestData);
            Assert.AreEqual(y, TestData.Base64TestData);
        }

        [TestMethod]
        public void GetDecodedLength()
        {
            int decodedLength = Utils.GetDecodedLength(TestData.StringTestData);
            Assert.AreEqual(2, decodedLength);
        }

        [TestMethod]
        public void GetEncodedLength()
        {
            int encodedLength = Utils.GetEncodedLength(TestData.BytesTestData);
            Assert.AreEqual(4, encodedLength);
        }

        [TestMethod]
        public void StringToByteArray()
        {
            byte[] data = new byte[] { 0x51, 0x55, 0x4a, 0x44 };
            CollectionAssert.AreEqual(Utils.StringToUtf8ByteArray(TestData.Base64TestData), data);
        }

        [TestMethod]
        public void ToBase64String()
        {
            Assert.AreEqual(Utils.EncodeToBase64String(TestData.BytesTestData), TestData.Base64TestData);
        }

        [TestMethod]
        public void ValidateSignature()
        {
            byte[] dataToEncrypt = Utils.StringToUtf8ByteArray(TestData.Base64TestData);
            byte[] password = Utils.StringToUtf8ByteArray(TestData.TestPassword);

            byte[] encryptResult = Managed.Encrypt(dataToEncrypt, password);

            Assert.IsFalse(Utils.ValidateSignature(dataToEncrypt, DataType.Cipher));
            Assert.IsTrue(Utils.ValidateSignature(encryptResult, DataType.Cipher));
        }

        [TestMethod]
        public void ValidateSignatureFromStream_BufferTooSmall()
        {
            Stream stream = new MemoryStream(new byte[] { 1, 2, 3, 4, 5 });

            bool validationResult = Utils.ValidateSignatureFromStream(stream, DataType.Cipher);

            Assert.AreEqual(validationResult, false);
        }

        [TestMethod]
        public void ValidateSignatureFromStream_ClosedStream()
        {
            Stream stream = new ClosedStream(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 });

            stream.Close();

            DevolutionsCryptoException exception = null;

            try
            {
                bool validationResult = Utils.ValidateSignatureFromStream(stream, DataType.Cipher);
            }
            catch (DevolutionsCryptoException ex)
            {
                exception = ex;
            }

            // Xamarin has a space between Cannot (Can not)
            bool validException = exception.ManagedException.Message.Contains("Cannot access a closed Stream.") || exception.ManagedException.Message.Contains("Can not access a closed Stream.");

            Assert.AreEqual(validException, true);
        }

        [TestMethod]
        public void ValidateSignatureFromStream_OriginalPosition()
        {
            Stream stream = new MemoryStream(TestData.EncryptedData);

            stream.Position = 12;

            bool validationResult = Utils.ValidateSignatureFromStream(stream, DataType.Cipher);

            Assert.AreEqual(stream.Position, 12);
            Assert.AreEqual(validationResult, false);
        }

        [TestMethod]
        public void ValidateSignatureFromStream_UnReadableStream()
        {
            Stream stream = new UnReadableStream(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 });

            DevolutionsCryptoException exception = null;

            try
            {
                bool validationResult = Utils.ValidateSignatureFromStream(stream, DataType.Cipher);
            }
            catch (DevolutionsCryptoException ex)
            {
                exception = ex;
            }

            Assert.AreEqual(exception.ManagedError, ManagedError.CanNotReadStream);
        }

        [TestMethod]
        public void ValidateSignatureFromStream_UnseekableStream()
        {
            Stream stream = new UnSeekableStream(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 });

            DevolutionsCryptoException exception = null;

            try
            {
                bool validationResult = Utils.ValidateSignatureFromStream(stream, DataType.Cipher);
            }
            catch (DevolutionsCryptoException ex)
            {
                exception = ex;
            }

            Assert.AreEqual(exception.ManagedError, ManagedError.CanNotSeekStream);
        }

        [TestMethod]
        public void ValidateSignatureFromStream_ValidSignature()
        {
            Stream stream = new MemoryStream(TestData.EncryptedData);

            bool validationResult = Utils.ValidateSignatureFromStream(stream, DataType.Cipher);

            Assert.AreEqual(validationResult, true);
        }
    }
}