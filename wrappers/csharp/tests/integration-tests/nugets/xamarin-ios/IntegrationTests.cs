#pragma warning disable SA1600 // Elements should be documented

#if DOTNET_FRAMEWORK
#pragma warning disable SA1300 // Element should begin with upper-case letter
namespace dotnet_framework
#pragma warning restore SA1300 // Element should begin with upper-case letter
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
#if XAMARIN_ANDROID
namespace xamarin_android
#endif
{
#if XAMARIN_MAC_FULL || XAMARIN_MAC_MODERN || XAMARIN_IOS || XAMARIN_ANDROID
    using NUnit.Framework;
    using TestClassAttribute = NUnit.Framework.TestFixtureAttribute;
    using TestMethodAttribute = NUnit.Framework.TestCaseAttribute;
#else
    using Microsoft.VisualStudio.TestTools.UnitTesting;
#endif
    using System;
    using System.Text;

    using Devolutions.Cryptography;
    using Devolutions.Cryptography.Argon2;
    using System.Runtime.InteropServices;

    [TestClass]
    public class IntegrationTests
    {
        [TestMethod]
        public void Tests()
        {
            string data = Devolutions.Cryptography.Managed.EncryptWithPasswordAsString("test", "tests");
            Console.WriteLine(data);

            Assert.IsTrue(!string.IsNullOrEmpty(data));

            IntPtr ptr = foo();

            Assert.IsTrue(ptr != IntPtr.Zero);
        }

        private const string LibName = "__Internal";

        [DllImport(LibName, EntryPoint = "foo", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr foo();

    }
}