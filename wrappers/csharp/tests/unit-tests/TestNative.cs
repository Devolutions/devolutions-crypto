namespace Devolutions.Crypto.Tests
{
    using Devolutions.Cryptography;
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
    public class TestNative
    {
    }
}