#if DOTNET_FRAMEWORK
namespace dotnet_framework
#endif
#if DOTNET_CORE
namespace dotnet_core
#endif
#if XAMARIN_MAC_FULL
namespace xamarin_mac_full
#endif
#if XAMARIN_MAC_MODERN
namespace xamarin_mac_modern
#endif
#if XAMARIN_IOS
namespace xamarin_ios
#endif
{
    using Devolutions.Cryptography;
    using Devolutions.Cryptography.Argon2;

#if XAMARIN_MAC_FULL || XAMARIN_MAC_MODERN || XAMARIN_IOS
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