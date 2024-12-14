#pragma warning disable SA1600 // Elements should be documented

namespace Devolutions.Crypto.Tests
{
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    using System;
    using System.Text;

    using Devolutions.Cryptography;
    using Devolutions.Cryptography.Argon2;
    using Devolutions.Cryptography.Signature;

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
        public void DecryptAsymmetricAadV2()
        {
            byte[] decryptResult = Managed.DecryptAsymmetric(
                Utils.Base64StringToByteArray("DQwCAAIAAgB1u62xYeyppWf83QdWwbwGUt5QuiAFZr+hIiFEvMRbXiNCE3RMBNbmgQkLr/vME0BeQa+uUTXZARvJcyNXHyAE4tSdw6o/psU/kw/Z/FbsPw=="),
                Utils.Base64StringToByteArray("DQwBAAEAAQC9qf9UY1ovL/48ALGHL9SLVpVozbdjYsw0EPerUl3zYA=="),
                aad: Utils.StringToUtf8ByteArray("this is some public data"));

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
        public void DecryptAadV1()
        {
            byte[] encryptedData = Utils.Base64StringToByteArray(
                "DQwCAAEAAQCeKfbTqYjfVCEPEiAJjiypBstPmZz0AnpliZKoR+WXTKdj2f/4ops0++dDBVZ+XdyE1KfqxViWVc9djy/HSCcPR4nDehtNI69heGCIFudXfQ==");
            byte[] encryptKey = Utils.Base64StringToByteArray("ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=");
            byte[] aad = Utils.StringToUtf8ByteArray("this is some public data");

            byte[] decryptResult = Managed.Decrypt(encryptedData, encryptKey, aad: aad);
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
        public void DecryptAadV2()
        {
            byte[] encryptedData = Utils.Base64StringToByteArray(
                "DQwCAAEAAgA9bh989dao0Pvaz1NpJTI5m7M4br2qVjZtFwXXoXZOlkCjtqU/uif4pbNCcpEodzeP4YG1QvfKVQ==");
            byte[] encryptKey = Utils.Base64StringToByteArray("ozJVEme4+5e/4NG3C+Rl26GQbGWAqGc0QPX8/1xvaFM=");
            byte[] aad = Utils.StringToUtf8ByteArray("this is some public data");

            byte[] decryptResult = Managed.Decrypt(encryptedData, encryptKey, aad: aad);
            string decryptResultAsUtf8String = Utils.ByteArrayToUtf8String(decryptResult);
            Assert.AreEqual(decryptResultAsUtf8String, "test Ciph3rtext~");
        }

        [TestMethod]
        public void DeriveKeyArgon2_Default()
        {
            Argon2Parameters parameters = Argon2Parameters.FromByteArray(Utils.Base64StringToByteArray("AQAAACAAAAABAAAAIAAAAAEAAAACEwAAAAAQAAAAimFBkm3f8+f+YfLRnF5OoQ=="));
            byte[] password = Utils.StringToUtf8ByteArray("password");

            byte[] derivedPassword = Managed.DeriveKeyArgon2(password, parameters);

            string derivedPasswordAsBase64String = Utils.EncodeToBase64String(derivedPassword);
            Assert.AreEqual(derivedPasswordAsBase64String, "AcEN6Cb1Om6tomZScAM725qiXMzaxaHlj3iMiT/Ukq0=");
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

        [TestMethod]
        public void SignatureV1()
        {
            byte[] data = Encoding.UTF8.GetBytes("this is a test");
            byte[] wrong_data = Encoding.UTF8.GetBytes("this is wrong");

            SigningPublicKey publicKey = SigningPublicKey.FromByteArray(Convert.FromBase64String("DQwFAAIAAQDeEvwlEigK5AXoTorhmlKP6+mbiUU2rYrVQ25JQ5xang=="));

            byte[] signature = Convert.FromBase64String("DQwGAAAAAQD82uRk4sFC8vEni6pDNw/vOdN1IEDg9cAVfprWJZ/JBls9Gi61cUt5u6uBJtseNGZFT7qKLvp4NUZrAOL8FH0K");

            Assert.IsTrue(Managed.VerifySignature(data, publicKey, signature));
            Assert.IsFalse(Managed.VerifySignature(wrong_data, publicKey, signature));
        }
    }
}
#pragma warning restore SA1600 // Elements should be documented