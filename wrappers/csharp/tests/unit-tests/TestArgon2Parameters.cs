#pragma warning disable SA1600 // Elements should be documented

namespace Devolutions.Crypto.Tests
{
    using System;
    using System.IO;

    using Devolutions.Cryptography.Argon2;

#if MACOS || ANDROID || IOS
    using NUnit.Framework;
    using NUnit.Framework.Legacy;
    using TestClassAttribute = NUnit.Framework.TestFixtureAttribute;
    using TestMethodAttribute = NUnit.Framework.TestCaseAttribute;
#else
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ClassicAssert = Microsoft.VisualStudio.TestTools.UnitTesting.Assert;
#endif

    [TestClass]
    public class TestArgon2Parameters
    {
        [TestMethod]
        public void FromByteArray()
        {
            Argon2Parameters parameters = Argon2Parameters.FromByteArray(Convert.FromBase64String(TestData.Argon2DefaultParametersb64));
            ClassicAssert.IsTrue(parameters.Iterations == 2);
            ClassicAssert.IsTrue(parameters.Lanes == 1);
            ClassicAssert.IsTrue(parameters.Length == 32);
            ClassicAssert.IsTrue(parameters.Memory == 4096);
        }

        [TestMethod]
        public void ToByteArray()
        {
            Argon2Parameters parameters = new Argon2Parameters();
            parameters.Memory = 4096;

            byte[] result = parameters.ToByteArray();

            ClassicAssert.IsTrue(result != null);

            ClassicAssert.IsTrue(result.Length == Argon2Parameters.NativeSize);

            MemoryStream stream = new MemoryStream(result);

            // ==== Devolutions Crypto Version ====
            byte[] buffer = new byte[4];

            stream.Read(buffer, 0, 4);

            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(buffer);
            }

            ClassicAssert.IsTrue(BitConverter.ToUInt32(buffer, 0) == 1);

            // ==== Length ====
            stream.Read(buffer, 0, 4);

            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(buffer);
            }

            ClassicAssert.IsTrue(BitConverter.ToUInt32(buffer, 0) == 32);

            // ==== Lanes ====
            stream.Read(buffer, 0, 4);

            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(buffer);
            }

            ClassicAssert.IsTrue(BitConverter.ToUInt32(buffer, 0) == 1);

            // ==== Memory ====
            stream.Read(buffer, 0, 4);

            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(buffer);
            }

            ClassicAssert.IsTrue(BitConverter.ToUInt32(buffer, 0) == 4096);

            // ==== Iterations ====
            stream.Read(buffer, 0, 4);

            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(buffer);
            }

            ClassicAssert.IsTrue(BitConverter.ToUInt32(buffer, 0) == 2);

            // ==== Variant ====
            stream.Read(buffer, 0, 1);

            ClassicAssert.IsTrue((Variant)buffer[0] == Variant.Argon2id);

            // ==== Version ====
            stream.Read(buffer, 0, 1);

            ClassicAssert.IsTrue((Devolutions.Cryptography.Argon2.Version)buffer[0] == Devolutions.Cryptography.Argon2.Version.Version13);
        }
    }
}
#pragma warning restore SA1600 // Elements should be documented