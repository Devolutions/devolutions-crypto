namespace Devolutions.Crypto.Tests
{
    using Devolutions.Cryptography;
    using Devolutions.Cryptography.Argon2;

#if XAMARIN_MAC_FULL || XAMARIN_MAC_MODERN || XAMARIN_IOS || XAMARIN_ANDROID
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