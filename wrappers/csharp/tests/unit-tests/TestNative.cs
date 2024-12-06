namespace Devolutions.Crypto.Tests
{
    using Devolutions.Cryptography;
    using Devolutions.Cryptography.Argon2;

#if MACOS || ANDROID || IOS
    using NUnit.Framework;
    using TestClassAttribute = NUnit.Framework.TestFixtureAttribute;
    using TestMethodAttribute = NUnit.Framework.TestCaseAttribute;
#else
    using Microsoft.VisualStudio.TestTools.UnitTesting;
#endif

    [TestClass]
    public class TestNative
    {
    }
}