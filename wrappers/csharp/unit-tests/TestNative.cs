#if DOTNET_FRAMEWORK
namespace dotnet_framework
#endif
#if DOTNET_CORE
namespace dotnet_core
#endif
#if XAMARIN_MAC_FULL
namespace xamarin_mac_full
#endif
{
    using Devolutions.Cryptography;
    using Devolutions.Cryptography.Argon2;

#if XAMARIN_MAC_FULL
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