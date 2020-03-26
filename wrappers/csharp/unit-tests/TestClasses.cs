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
    using System.Diagnostics.CodeAnalysis;
    using System.IO;

    [SuppressMessage("Microsoft.StyleCop.CSharp.MaintainabilityRules", "SA1402:FileMayOnlyContainASingleClass", Justification = "Test Class")]
    [SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1649:File name should match first type name", Justification = "Test Class")]
    public class UnSeekableStream : MemoryStream
    {
        public UnSeekableStream(byte[] buffer) : base(buffer)
        {
        }

        public override bool CanSeek
        {
            get
            {
                return false;
            }
        }
    }

    [SuppressMessage("Microsoft.StyleCop.CSharp.MaintainabilityRules", "SA1402:FileMayOnlyContainASingleClass", Justification = "Test Class")]
    public class UnReadableStream : MemoryStream
    {
        public UnReadableStream(byte[] buffer) : base(buffer)
        {
        }

        public override bool CanRead
        {
            get
            {
                return false;
            }
        }
    }

    [SuppressMessage("Microsoft.StyleCop.CSharp.MaintainabilityRules", "SA1402:FileMayOnlyContainASingleClass", Justification = "Test Class")]
    public class ClosedStream : MemoryStream
    {
        public ClosedStream(byte[] buffer) : base(buffer)
        {
        }

        public override bool CanRead
        {
            get
            {
                return true;
            }
        }

        public override bool CanSeek
        {
            get
            {
                return true;
            }
        }
    }
}
#pragma warning restore SA1600 // Elements should be documented