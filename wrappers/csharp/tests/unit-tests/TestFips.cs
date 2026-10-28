#pragma warning disable SA1600 // Elements should be documented
namespace Devolutions.Crypto.Tests
{
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    using System;
    using System.Text;

    using Devolutions.Cryptography;
    using Devolutions.Cryptography.Signature;

    // These tests need a native library built with the `fips` feature, and are inconclusive otherwise.
    [TestClass]
    public class TestFips
    {
        private static readonly byte[] Data = Encoding.UTF8.GetBytes("this is some FIPS test data");

        [TestMethod]
        public void NonFipsBuildIsNotInFipsMode()
        {
            if (IsFipsBuild())
            {
                Assert.Inconclusive("The native library is built with the fips feature.");
            }

            Assert.IsFalse(Utils.IsFipsMode());
        }

        [TestMethod]
        public void SymmetricV3()
        {
            RequireFipsBuild();

            byte[] key = Managed.GenerateKey(32);
            byte[] encrypted = Managed.Encrypt(Data, key)!;

            Assert.AreEqual(3, Version(encrypted));
            CollectionAssert.AreEqual(Data, Managed.Decrypt(encrypted, key));
        }

        [TestMethod]
        public void AsymmetricV3()
        {
            RequireFipsBuild();

            KeyPair keypair = Managed.GenerateKeyPair();
            byte[] encrypted = Managed.EncryptAsymmetric(Data, keypair.PublicKey!)!;

            Assert.AreEqual(3, Version(keypair.PublicKey!));
            Assert.AreEqual(3, Version(encrypted));
            CollectionAssert.AreEqual(Data, Managed.DecryptAsymmetric(encrypted, keypair.PrivateKey!));
        }

        [TestMethod]
        public void SignatureV3()
        {
            RequireFipsBuild();

            SigningKeyPair keypair = Managed.GenerateSigningKeyPair();
            byte[] signature = Managed.Sign(Data, keypair)!;

            Assert.AreEqual(3, Version(signature));
            Assert.IsTrue(Managed.VerifySignature(Data, keypair.GetPublicKey(), signature));
            Assert.IsFalse(Managed.VerifySignature(Encoding.UTF8.GetBytes("wrong data"), keypair.GetPublicKey(), signature));
        }

        [TestMethod]
        public void PasswordHashV3()
        {
            RequireFipsBuild();

            byte[] password = Encoding.UTF8.GetBytes("a very strong password");
            byte[] hash = Managed.HashPassword(password);

            Assert.AreEqual(3, Version(hash));
            Assert.IsTrue(Managed.VerifyPassword(password, hash));
            Assert.IsFalse(Managed.VerifyPassword(Encoding.UTF8.GetBytes("wrong password"), hash));
        }

        [TestMethod]
        public void LegacyEncryptionIsRejected()
        {
            RequireFipsBuild();

            byte[] key = Managed.GenerateKey(32);

            DevolutionsCryptoException exception = Assert.ThrowsException<DevolutionsCryptoException>(() => Managed.Encrypt(Data, key, version: CipherTextVersion.V2));
            Assert.AreEqual(NativeError.NotFipsApproved, exception.NativeError);

            exception = Assert.ThrowsException<DevolutionsCryptoException>(() => Managed.HashPassword(Data, PasswordHashVersion.V2));
            Assert.AreEqual(NativeError.NotFipsApproved, exception.NativeError);
        }

        [TestMethod]
        public void LegacyDecryptionStillWorks()
        {
            RequireFipsBuild();

            byte[]? decryptResult = Managed.Decrypt(TestData.EncryptedData, TestData.BytesTestKey);
            Assert.AreEqual(TestData.Base64TestData, Utils.ByteArrayToUtf8String(decryptResult));
        }

        // V3 only exists when the native library is built with the `fips` feature.
        private static bool IsFipsBuild()
        {
            try
            {
                Managed.Encrypt(Data, Managed.GenerateKey(32), version: CipherTextVersion.V3);
                return true;
            }
            catch (DevolutionsCryptoException)
            {
                return false;
            }
        }

        private static void RequireFipsBuild()
        {
            if (!IsFipsBuild())
            {
                Assert.Inconclusive("The native library is not built with the fips feature.");
            }
        }

        private static int Version(byte[] data)
        {
            return BitConverter.ToUInt16(data, 6);
        }
    }
}
