#pragma warning disable SA1600 // Elements should be documented

namespace Devolutions.Crypto.Tests
{
#if XAMARIN_MAC_FULL || XAMARIN_MAC_MODERN || XAMARIN_IOS || XAMARIN_ANDROID
    using NUnit.Framework;
    using TestClassAttribute = NUnit.Framework.TestFixtureAttribute;
    using TestMethodAttribute = NUnit.Framework.TestCaseAttribute;
#else
    using Microsoft.VisualStudio.TestTools.UnitTesting;
#endif
    using System;
    using System.IO;

    using Devolutions.Cryptography;

    [TestClass]
    public class TestUtils
    {
        [TestMethod]
        public void Base64StringToByteArray()
        {
            byte[] data = Utils.Base64StringToByteArray(TestData.Base64TestData);
            Assert.AreEqual(Convert.ToBase64String(data), Convert.ToBase64String(TestData.BytesTestData));
        }

        [TestMethod]
        public void ByteArrayToString()
        {
            byte[] data = new byte[] { 0x51, 0x55, 0x4a, 0x44 };
            string dataToUtf8String = Utils.ByteArrayToUtf8String(data);
            Assert.AreEqual(dataToUtf8String, TestData.Base64TestData);
        }

        [TestMethod]
        public void ConstantTimeEqual()
        {
            byte[] x = { 0, 1, 2 };
            byte[] y = { 4, 5, 6 };
            byte[] z = { 0, 1, 2, 3 };

            Assert.IsTrue(Utils.ConstantTimeEquals(x, x));
            Assert.IsTrue(!Utils.ConstantTimeEquals(x, y));
            Assert.IsTrue(!Utils.ConstantTimeEquals(x, z));
            Assert.IsTrue(!Utils.ConstantTimeEquals(y, x));
            Assert.IsTrue(Utils.ConstantTimeEquals(y, y));
            Assert.IsTrue(!Utils.ConstantTimeEquals(y, z));
            Assert.IsTrue(!Utils.ConstantTimeEquals(z, x));
            Assert.IsTrue(!Utils.ConstantTimeEquals(z, y));
            Assert.IsTrue(Utils.ConstantTimeEquals(z, z));
        }

        [TestMethod]
        public void Decode()
        {
            byte[] decodedData = Utils.DecodeFromBase64(TestData.Base64TestData);
            Assert.AreEqual(Convert.ToBase64String(decodedData), Convert.ToBase64String(TestData.BytesTestData));
        }

        [TestMethod]
        public void DecodeUrl()
        {
            byte[] d1 = Utils.DecodeFromBase64Url(TestData.Base64Url1);
            byte[] d2 = Utils.DecodeFromBase64Url(TestData.Base64Url2);
            byte[] d3 = Utils.DecodeFromBase64Url(TestData.Base64Url3);
            Assert.AreEqual(Convert.ToBase64String(d1), Convert.ToBase64String(TestData.Base64UrlBytes1));
            Assert.AreEqual(Convert.ToBase64String(d2), Convert.ToBase64String(TestData.Base64UrlBytes2));
            Assert.AreEqual(Convert.ToBase64String(d3), Convert.ToBase64String(TestData.Base64UrlBytes3));
        }

        [TestMethod]
        public void Encode()
        {
            string y = Utils.EncodeToBase64String(TestData.BytesTestData);
            Assert.AreEqual(y, TestData.Base64TestData);
        }

        [TestMethod]
        public void EncodeUrl()
        {
            string e1 = Utils.EncodeToBase64UrlString(TestData.Base64UrlBytes1);
            string e2 = Utils.EncodeToBase64UrlString(TestData.Base64UrlBytes2);
            string e3 = Utils.EncodeToBase64UrlString(TestData.Base64UrlBytes3);
            Assert.AreEqual(e1, TestData.Base64Url1);
            Assert.AreEqual(e2, TestData.Base64Url2);
            Assert.AreEqual(e3, TestData.Base64Url3);
        }

        [TestMethod]
        public void GetDecodedLength()
        {
            Assert.IsTrue(this.GetDotNetBase64Length(TestData.StringTestData) <= Utils.GetDecodedBase64StringLength(TestData.StringTestData)); // Invalid data
            Assert.IsTrue(Utils.GetDecodedBase64StringLength("====") >= this.GetDotNetBase64Length("===="));
            Assert.IsTrue(Utils.GetDecodedBase64StringLength("=") == this.GetDotNetBase64Length("="));
            Assert.IsTrue(Utils.GetDecodedBase64StringLength("YWxsbw==") == this.GetDotNetBase64Length("YWxsbw=="));
            Assert.IsTrue(Utils.GetDecodedBase64StringLength(null) == this.GetDotNetBase64Length(null));
        }

        public int GetDotNetBase64Length(string base64)
        {
            try
            {
                byte[] test = Convert.FromBase64String(base64);

                return test.Length;
            }
            catch (Exception)
            {
                return 0;
            }
        }

        [TestMethod]
        public void GetEncodedLength()
        {
            int encodedLength = Utils.GetEncodedBase64StringLength(TestData.BytesTestData);
            Assert.AreEqual(4, encodedLength);
        }

        [TestMethod]
        public void ScryptSimple()
        {
            byte[] password = Utils.StringToUtf8ByteArray(TestData.TestPassword);
            byte[] salt = TestData.Salt;

            string hash = Utils.ScryptSimple(password, salt, 10, 8, 1);

            Assert.AreEqual(TestData.ScryptHash, hash);
        }

        [TestMethod]
        public void StringToByteArray()
        {
            byte[] data = new byte[] { 0x51, 0x55, 0x4a, 0x44 };
            Assert.AreEqual(Convert.ToBase64String(Utils.StringToUtf8ByteArray(TestData.Base64TestData)), Convert.ToBase64String(data));
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

            Assert.IsFalse(Utils.ValidateHeader(dataToEncrypt, DataType.Cipher));
            Assert.IsTrue(Utils.ValidateHeader(encryptResult, DataType.Cipher));
        }

        [TestMethod]
        public void ValidateSignatureFromStream_BufferTooSmall()
        {
            Stream stream = new MemoryStream(new byte[] { 1, 2, 3, 4, 5 });

            bool validationResult = Utils.ValidateHeaderFromStream(stream, DataType.Cipher);

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
                bool validationResult = Utils.ValidateHeaderFromStream(stream, DataType.Cipher);
            }
            catch (DevolutionsCryptoException ex)
            {
                exception = ex;
            }

            // Xamarin has a space between Cannot (Can not)
            bool validException = exception.ManagedException.Message.Contains("Cannot access a closed Stream.")
                || exception.ManagedException.Message.Contains("Can not access a closed Stream.");

            Assert.AreEqual(validException, true);
        }

        [TestMethod]
        public void ValidateSignatureFromStream_OriginalPosition()
        {
            Stream stream = new MemoryStream(TestData.EncryptedData);

            stream.Position = 12;

            bool validationResult = Utils.ValidateHeaderFromStream(stream, DataType.Cipher);

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
                bool validationResult = Utils.ValidateHeaderFromStream(stream, DataType.Cipher);
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
                bool validationResult = Utils.ValidateHeaderFromStream(stream, DataType.Cipher);
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

            bool validationResult = Utils.ValidateHeaderFromStream(stream, DataType.Cipher);

            Assert.AreEqual(validationResult, true);
        }
    }
}

#pragma warning restore SA1600 // Elements should be documented