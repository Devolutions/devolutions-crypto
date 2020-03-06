namespace Devolutions.Cryptography
{
    using System;

    public enum ManagedError
    {
        InvalidParameter,

        IncompatibleVersion,

        CanNotSeekStream,

        CanNotReadStream,

        Error
    }

    public class DevolutionsCryptoException : Exception
    {
        public DevolutionsCryptoException(ManagedError managedError, string message = null, Exception exception = null) : base(message)
        {
            this.ManagedError = managedError;
            this.ManagedException = exception;
        }

        public DevolutionsCryptoException(NativeError nativeError, string message = null, Exception exception = null) : base(message)
        {
            this.NativeError = nativeError;
            this.ManagedException = exception;
        }

        public ManagedError? ManagedError { get; set; }

        public Exception ManagedException { get; set; }

        public override string Message
        {
            get
            {
                return this.GetDetailedMessage() + "===Original Message===\r\n" + base.Message;
            }
        }

        public NativeError? NativeError { get; set; }

        public override string StackTrace
        {
            get
            {
                return this.GetDetailedStackTrace() + "===Original StackTrace===\r\n" + base.StackTrace;
            }
        }

        public string GetDetailedMessage()
        {
            string result = string.Empty;

            if (this.NativeError != null)
            {
                result = "NativeError :\r\n";
                result = result + this.NativeError.Value.ToString() + "\r\n";

                if (this.Data != null)
                {
                    this.Data["NativeError"] = this.NativeError.Value.ToString();
                }
            }

            if (this.ManagedError != null)
            {
                result = "ManagedError : \r\n";
                result = result + this.ManagedError.Value.ToString() + "\r\n";

                if (this.Data != null)
                {
                    this.Data["ManagedError"] = this.ManagedError.Value.ToString();
                }

                if (this.ManagedException != null)
                {
                    result = this.ManagedException.Message + "\r\n";
                }
            }

            return result;
        }

        public string GetDetailedStackTrace()
        {
            string result = string.Empty;

            if (this.ManagedException != null)
            {
                result = "ManagedException :\r\n";
                result += this.ManagedException.StackTrace + "\r\n";
            }

            return result;
        }
    }
}