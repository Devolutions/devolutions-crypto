#pragma warning disable SA1600 // Elements should be documented

#if DOTNET_FRAMEWORK
#pragma warning disable SA1300 // Element should begin with upper-case letter
namespace dotnet_framework
#pragma warning restore SA1300 // Element should begin with upper-case letter
#endif
#if DOTNET_CORE
namespace dotnet_core
#endif
#if XAMARIN_MAC_FULL
namespace xamarin_mac_full
#endif
#if XAMARIN_MAC_MODERN
namespace xamarin_mac_modern
#endif
#if XAMARIN_IOS
namespace xamarin_ios
#endif
{
#if XAMARIN_MAC_FULL || XAMARIN_MAC_MODERN || XAMARIN_IOS
    using NUnit.Framework;
    using TestClassAttribute = NUnit.Framework.TestFixtureAttribute;
    using TestMethodAttribute = NUnit.Framework.TestCaseAttribute;
#else
    using Microsoft.VisualStudio.TestTools.UnitTesting;
#endif
    using Devolutions.Cryptography;
    using Devolutions.Cryptography.Argon2;

    [TestClass]
    public class Conformity
    {
        [TestMethod]
        public void DecryptAsymmetricV2()
        {
            byte[] decryptResult = Managed.DecryptAsymmetric(
                Utils.Base64StringToByteArray("DQwCAAIAAgCIG9L2MTiumytn7H/p5I3aGVdhV3WUL4i8nIeMWIJ1YRbNQ6lEiQDAyfYhbs6gg1cD7+5Ft2Q5cm7ArsGfiFYWnscm1y7a8tAGfjFFTonzrg=="),
                Utils.Base64StringToByteArray("DQwBAAEAAQAAwQ3oJvU6bq2iZlJwAzvbmqJczNrFoeWPeIyJP9SSbQ=="));

            Assert.IsTrue(Utils.ByteArrayToUtf8String(decryptResult) == "testdata");
        }

        [TestMethod]
        public void DecryptV1()
        {
            byte[] encryptedData = Utils.Base64StringToByteArray(
                "DQwCAAAAAQCK1twEut+TeJfFbTWCRgHjyS6bOPOZUEQAeBtSFFRl2jHggM/34n68zIZWGbsZHkufVzU6mTN5N2Dx9bTplrycv5eNVevT4P9FdVHJ751D+A==");
            byte[] encryptKey = Utils.Base64StringToByteArray("ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=");

            byte[] decryptResult = Managed.Decrypt(encryptedData, encryptKey);
            string decryptResultAsUtf8String = Utils.ByteArrayToUtf8String(decryptResult);
            Assert.AreEqual(decryptResultAsUtf8String, "test Ciph3rtext~");
        }

        [TestMethod]
        public void DecryptV2()
        {
            byte[] encryptedData = Utils.Base64StringToByteArray("DQwCAAAAAgAA0iPpI4IEzcrWAQiy6tqDqLbRYduGvlMC32mVH7tpIN2CXDUu5QHF91I7pMrmjt/61pm5CeR/IcU=");
            byte[] encryptKey = Utils.Base64StringToByteArray("ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=");

            byte[] decryptResult = Managed.Decrypt(encryptedData, encryptKey);
            string decryptResultAsUtf8String = Utils.ByteArrayToUtf8String(decryptResult);
            Assert.AreEqual(decryptResultAsUtf8String, "test Ciph3rtext~2");
        }

        [TestMethod]
        public void DeriveKey_Default()
        {
            byte[] encodedPassword = Utils.StringToUtf8ByteArray("testpassword");
            byte[] derivedPassword = Managed.DeriveKey(encodedPassword);
            string derivedPasswordAsBase64String = Utils.EncodeToBase64String(derivedPassword);
            Assert.AreEqual(derivedPasswordAsBase64String, "ImfGCyv6PwMYaJShGxR4MfVrjuUrsI0CSarJgOApwf8=");
        }

        [TestMethod]
        public void DeriveKey_Iterations()
        {
            byte[] encodedPassword = Utils.StringToUtf8ByteArray("testPa$$");
            byte[] derivedPassword = Managed.DeriveKey(encodedPassword, null, 100);
            string derivedPasswordAsBase64String = Utils.EncodeToBase64String(derivedPassword);
            Assert.AreEqual(derivedPasswordAsBase64String, "ev/GiJLvOgIkkWrnIrHSi2fdZE5qJBIrW+DLeMLIXK4=");
        }

        [TestMethod]
        public void DeriveKey_Salt()
        {
            byte[] encodedPassword = Utils.StringToUtf8ByteArray("testPa$$");
            byte[] saltBytes = Utils.DecodeFromBase64("tdTt5wgeqQYLvkiXKkFirqy2hMbzadBtL+jekVeNCRA=");
            byte[] derivedPassword = Managed.DeriveKey(encodedPassword, saltBytes, 100);
            string derivedPasswordAsBase64String = Utils.EncodeToBase64String(derivedPassword);
            Assert.AreEqual(derivedPasswordAsBase64String, "ZaYRZeQiIPJ+Jl511AgHZjv4/HbCFq4eUP9yNa3gowI=");
        }

        [TestMethod]
        public void DeriveKeyPair()
        {
            KeyPair keyPair = Managed.DeriveKeyPair(
                Utils.StringToUtf8ByteArray("password"),
                Argon2Parameters.FromByteArray(Utils.DecodeFromBase64("AQAAACAAAAABAAAAIAAAAAEAAAACEwAAAAAQAAAAimFBkm3f8+f+YfLRnF5OoQ==")));

            Assert.IsTrue(keyPair.PrivateKeyString == "DQwBAAEAAQAAwQ3oJvU6bq2iZlJwAzvbmqJczNrFoeWPeIyJP9SSbQ==");
            Assert.IsTrue(keyPair.PublicKeyString == "DQwBAAIAAQBwfx5kOF4iEHXF+jyYRjfQYZnGCy0SQMHeRZCxRVvmCg==");
        }

        [TestMethod]
        public void VerifyPasswordV1_Default()
        {
            bool result = Managed.VerifyPassword(
                Utils.StringToUtf8ByteArray("password1"),
                Utils.DecodeFromBase64("DQwDAAAAAQAQJwAAXCzLFoyeZhFSDYBAPiIWhCk04aoP/lalOoCl7D+skIY/i+3WT7dn6L8WvnfEq6flCd7i+IcKb3GEK4rCpzhDlw=="));

            Assert.IsTrue(result);
        }

        [TestMethod]
        public void VerifyPasswordV1_Iterations()
        {
            bool result = Managed.VerifyPassword(
                Utils.StringToUtf8ByteArray("password1"),
                Utils.DecodeFromBase64("DQwDAAAAAQAKAAAAmH1BBckBJYDD0xfiwkAk1xwKgw8a57YQT0Igm+Faa9LFamTeEJgqn/qHc2R/8XEyK2iLPkVy+IErdGLLtLKJ2g=="));

            Assert.IsTrue(result);
        }
    }
}
#pragma warning restore SA1600 // Elements should be documented