#pragma warning disable SA1600 // Elements should be documented

namespace Devolutions.Crypto.Tests
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