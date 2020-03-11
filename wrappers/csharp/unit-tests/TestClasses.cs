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
    using System.Diagnostics.CodeAnalysis;
    using System.IO;

    [SuppressMessage("Microsoft.StyleCop.CSharp.MaintainabilityRules", "SA1402:FileMayOnlyContainASingleClass", Justification = "Test Class")]
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