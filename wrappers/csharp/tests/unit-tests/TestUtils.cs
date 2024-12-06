#pragma warning disable SA1600 // Elements should be documented

namespace Devolutions.Crypto.Tests
{
#if MACOS || ANDROID || IOS
    using NUnit.Framework;
    using NUnit.Framework.Legacy;
    using TestClassAttribute = NUnit.Framework.TestFixtureAttribute;
    using TestMethodAttribute = NUnit.Framework.TestCaseAttribute;
#else
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ClassicAssert = Microsoft.VisualStudio.TestTools.UnitTesting.Assert;
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
            ClassicAssert.AreEqual(Convert.ToBase64String(data), Convert.ToBase64String(TestData.BytesTestData));
        }

        [TestMethod]
        public void ByteArrayToString()
        {
            byte[] data = new byte[] { 0x51, 0x55, 0x4a, 0x44 };
            string dataToUtf8String = Utils.ByteArrayToUtf8String(data);
            ClassicAssert.AreEqual(dataToUtf8String, TestData.Base64TestData);
        }

        [TestMethod]
        public void ConstantTimeEqual()
        {
            byte[] x = { 0, 1, 2 };
            byte[] y = { 4, 5, 6 };
            byte[] z = { 0, 1, 2, 3 };

            ClassicAssert.IsTrue(Utils.ConstantTimeEquals(x, x));
            ClassicAssert.IsTrue(!Utils.ConstantTimeEquals(x, y));
            ClassicAssert.IsTrue(!Utils.ConstantTimeEquals(x, z));
            ClassicAssert.IsTrue(!Utils.ConstantTimeEquals(y, x));
            ClassicAssert.IsTrue(Utils.ConstantTimeEquals(y, y));
            ClassicAssert.IsTrue(!Utils.ConstantTimeEquals(y, z));
            ClassicAssert.IsTrue(!Utils.ConstantTimeEquals(z, x));
            ClassicAssert.IsTrue(!Utils.ConstantTimeEquals(z, y));
            ClassicAssert.IsTrue(Utils.ConstantTimeEquals(z, z));
        }

        [TestMethod]
        public void Decode()
        {
            byte[] decodedData = Utils.DecodeFromBase64(TestData.Base64TestData);
            ClassicAssert.AreEqual(Convert.ToBase64String(decodedData), Convert.ToBase64String(TestData.BytesTestData));
        }

        [TestMethod]
        public void DecodeUrl()
        {
            byte[] d1 = Utils.DecodeFromBase64Url(TestData.Base64Url1);
            byte[] d2 = Utils.DecodeFromBase64Url(TestData.Base64Url2);
            byte[] d3 = Utils.DecodeFromBase64Url(TestData.Base64Url3);
            ClassicAssert.AreEqual(Convert.ToBase64String(d1), Convert.ToBase64String(TestData.Base64UrlBytes1));
            ClassicAssert.AreEqual(Convert.ToBase64String(d2), Convert.ToBase64String(TestData.Base64UrlBytes2));
            ClassicAssert.AreEqual(Convert.ToBase64String(d3), Convert.ToBase64String(TestData.Base64UrlBytes3));
        }

        [TestMethod]
        public void Encode()
        {
            string y = Utils.EncodeToBase64String(TestData.BytesTestData);
            ClassicAssert.AreEqual(y, TestData.Base64TestData);
        }

        [TestMethod]
        public void EncodeUrl()
        {
            string e1 = Utils.EncodeToBase64UrlString(TestData.Base64UrlBytes1);
            string e2 = Utils.EncodeToBase64UrlString(TestData.Base64UrlBytes2);
            string e3 = Utils.EncodeToBase64UrlString(TestData.Base64UrlBytes3);
            ClassicAssert.AreEqual(e1, TestData.Base64Url1);
            ClassicAssert.AreEqual(e2, TestData.Base64Url2);
            ClassicAssert.AreEqual(e3, TestData.Base64Url3);
        }

        [TestMethod]
        public void GetDecodedLength()
        {
            ClassicAssert.IsTrue(this.GetDotNetBase64Length(TestData.StringTestData) <= Utils.GetDecodedBase64StringLength(TestData.StringTestData)); // Invalid data
            ClassicAssert.IsTrue(Utils.GetDecodedBase64StringLength("====") >= this.GetDotNetBase64Length("===="));
            ClassicAssert.IsTrue(Utils.GetDecodedBase64StringLength("=") == this.GetDotNetBase64Length("="));
            ClassicAssert.IsTrue(Utils.GetDecodedBase64StringLength("YWxsbw==") == this.GetDotNetBase64Length("YWxsbw=="));
            ClassicAssert.IsTrue(Utils.GetDecodedBase64StringLength(null) == this.GetDotNetBase64Length(null));
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
            ClassicAssert.AreEqual(4, encodedLength);
        }

        [TestMethod]
        public void ScryptSimple()
        {
            byte[] password = Utils.StringToUtf8ByteArray(TestData.TestPassword);
            byte[] salt = TestData.Salt;

            string hash = Utils.ScryptSimple(password, salt, 10, 8, 1);

            ClassicAssert.AreEqual(TestData.ScryptHash, hash);
        }

        [TestMethod]
        public void StringToByteArray()
        {
            byte[] data = new byte[] { 0x51, 0x55, 0x4a, 0x44 };
            ClassicAssert.AreEqual(Convert.ToBase64String(Utils.StringToUtf8ByteArray(TestData.Base64TestData)), Convert.ToBase64String(data));
        }

        [TestMethod]
        public void ToBase64String()
        {
            ClassicAssert.AreEqual(Utils.EncodeToBase64String(TestData.BytesTestData), TestData.Base64TestData);
        }

        [TestMethod]
        public void ValidateSignature()
        {
            byte[] dataToEncrypt = Utils.StringToUtf8ByteArray(TestData.Base64TestData);
            byte[] password = Utils.StringToUtf8ByteArray(TestData.TestPassword);

            byte[] encryptResult = Managed.Encrypt(dataToEncrypt, password);

            ClassicAssert.IsFalse(Utils.ValidateHeader(dataToEncrypt, DataType.Cipher));
            ClassicAssert.IsTrue(Utils.ValidateHeader(encryptResult, DataType.Cipher));
        }

        [TestMethod]
        public void ValidateSignatureFromStream_BufferTooSmall()
        {
            Stream stream = new MemoryStream(new byte[] { 1, 2, 3, 4, 5 });

            bool validationResult = Utils.ValidateHeaderFromStream(stream, DataType.Cipher);

            ClassicAssert.AreEqual(validationResult, false);
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

            ClassicAssert.AreEqual(validException, true);
        }

        [TestMethod]
        public void ValidateSignatureFromStream_OriginalPosition()
        {
            Stream stream = new MemoryStream(TestData.EncryptedData);

            stream.Position = 12;

            bool validationResult = Utils.ValidateHeaderFromStream(stream, DataType.Cipher);

            ClassicAssert.AreEqual(stream.Position, 12);
            ClassicAssert.AreEqual(validationResult, false);
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

            ClassicAssert.AreEqual(exception.ManagedError, ManagedError.CanNotReadStream);
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

            ClassicAssert.AreEqual(exception.ManagedError, ManagedError.CanNotSeekStream);
        }

        [TestMethod]
        public void ValidateSignatureFromStream_ValidSignature()
        {
            Stream stream = new MemoryStream(TestData.EncryptedData);

            bool validationResult = Utils.ValidateHeaderFromStream(stream, DataType.Cipher);

            ClassicAssert.AreEqual(validationResult, true);
        }
    }
}

#pragma warning restore SA1600 // Elements should be documented