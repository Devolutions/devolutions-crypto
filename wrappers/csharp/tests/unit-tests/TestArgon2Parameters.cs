#pragma warning disable SA1600 // Elements should be documented

namespace Devolutions.Crypto.Tests
{
    using System;
    using System.IO;

    using Devolutions.Cryptography.Argon2;

    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class TestArgon2Parameters
    {
        [TestMethod]
        public void FromByteArray()
        {
            Argon2Parameters? parameters = Argon2Parameters.FromByteArray(Convert.FromBase64String(TestData.Argon2DefaultParametersb64));
            Assert.IsNotNull(parameters);
            Assert.IsTrue(parameters.Iterations == 2);
            Assert.IsTrue(parameters.Lanes == 1);
            Assert.IsTrue(parameters.Length == 32);
            Assert.IsTrue(parameters.Memory == 4096);
        }

        [TestMethod]
        public void ToByteArray()
        {
            Argon2Parameters parameters = new Argon2Parameters();
            parameters.Memory = 4096;

            byte[] result = parameters.ToByteArray();

            Assert.IsTrue(result != null);

            Assert.IsTrue(result.Length == Argon2Parameters.NativeSize);

            MemoryStream stream = new MemoryStream(result);

            // ==== Devolutions Crypto Version ====
            byte[] buffer = new byte[4];

            stream.Read(buffer, 0, 4);

            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(buffer);
            }

            Assert.IsTrue(BitConverter.ToUInt32(buffer, 0) == 1);

            // ==== Length ====
            stream.Read(buffer, 0, 4);

            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(buffer);
            }

            Assert.IsTrue(BitConverter.ToUInt32(buffer, 0) == 32);

            // ==== Lanes ====
            stream.Read(buffer, 0, 4);

            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(buffer);
            }

            Assert.IsTrue(BitConverter.ToUInt32(buffer, 0) == 1);

            // ==== Memory ====
            stream.Read(buffer, 0, 4);

            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(buffer);
            }

            Assert.IsTrue(BitConverter.ToUInt32(buffer, 0) == 4096);

            // ==== Iterations ====
            stream.Read(buffer, 0, 4);

            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(buffer);
            }

            Assert.IsTrue(BitConverter.ToUInt32(buffer, 0) == 2);

            // ==== Variant ====
            stream.Read(buffer, 0, 1);

            Assert.IsTrue((Variant)buffer[0] == Variant.Argon2id);

            // ==== Version ====
            stream.Read(buffer, 0, 1);

            Assert.IsTrue((Devolutions.Cryptography.Argon2.Version)buffer[0] == Devolutions.Cryptography.Argon2.Version.Version13);
        }
    }
}
#pragma warning restore SA1600 // Elements should be documented