namespace dotnet_core
{
    using System;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Devolutions.Cryptography;

    [TestClass]
    public class UnitTest
    {
        [TestMethod]
        public void TestMethod()
        {
            try
            {
                string encryptResult = Devolutions.Cryptography.Managed.EncryptWithPasswordAsString("SomeData", "SomePassword");

                string decryptResult = Devolutions.Cryptography.Managed.DecryptWithPasswordAsString(encryptResult, "SomePassword");

                if (decryptResult != "SomeData")
                {
                    throw new Exception();
                }

                encryptResult = null;
                decryptResult = null;

                encryptResult = Devolutions.Cryptography.Managed.EncryptWithPasswordAsString("SomeData", "SomePassword", cipher_version: CipherVersion.V1);

                decryptResult = Devolutions.Cryptography.Managed.DecryptWithPasswordAsString(encryptResult, "SomePassword");

                if (decryptResult != "SomeData")
                {
                    throw new Exception();
                }

                encryptResult = null;
                decryptResult = null;

                encryptResult = Devolutions.Cryptography.Managed.EncryptWithPasswordAsString("SomeData", "SomePassword", cipher_version: CipherVersion.V2);
                
                decryptResult = Devolutions.Cryptography.Managed.DecryptWithPasswordAsString(encryptResult, "SomePassword");
                
                if (decryptResult != "SomeData")
                {
                    throw new Exception();
                }
            }
            catch(DevolutionsCryptoException ex)
            {
                if (ex.NativeError != null)
                {
                    Console.WriteLine(ex.NativeError.ToString());
                }

                if (ex.ManagedError != null)
                {
                    Console.WriteLine(ex.ManagedError.ToString());
                }

                throw ex;
            }
        }
    }
}
