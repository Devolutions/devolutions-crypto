using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Devolutions.Cryptography;

namespace Tests
{
    [TestClass]
    public class TestUtils
    {
        [TestMethod]
        public void TestMethod1()
        {
            Assert.AreEqual(Utils.ToBase64String(new byte[]{0x41, 0x42, 0x43}), "QUJD");
        }
    }
}
