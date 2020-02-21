using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Devolutions.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests
{
    [TestClass]
    public class TestManaged
    {
        [TestMethod]
        public void ToBase64String()
        {
            var x = Utils.StringToByteArray("QUJD");
            var y = "pwd";
            var z = Managed.DecryptWithPasswordAsString(x, y, 100);
            Assert.AreEqual(z, "QUJD");
        }

        [TestMethod]
        public void X()
        {
            var x = Utils.Base64StringToByteArray("QUJD");
            var z = Managed.DeriveKey(x, null, 100);
            Assert.AreEqual(z, "QUJD");
        }
    }
}
