using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace dotnet_framework
{
    [TestClass]
    public class UnitTest
    {
        [TestMethod]
        public void TestMethod()
        {
            string encryptResult = Devolutions.Cryptography.Managed.EncryptWithPasswordAsString("SomeData", "SomePassword");

            string decryptResult = Devolutions.Cryptography.Managed.DecryptWithPasswordAsString(encryptResult, "SomePassword");

            if (decryptResult != "SomeData")
            {
                throw new Exception();
            }
        }
    }
}
