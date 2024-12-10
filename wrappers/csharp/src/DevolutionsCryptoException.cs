namespace Devolutions.Cryptography
{
    using System;

    /// <summary>
    /// Wrapper for native exceptions & managed exceptions in the library.
    /// </summary>
    public class DevolutionsCryptoException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DevolutionsCryptoException"/> class.
        /// </summary>
        /// <param name="managedError">The managed error code.</param>
        /// <param name="message">The exception message. (Optional).</param>
        /// <param name="exception">The managed exception. (Optional).</param>
        public DevolutionsCryptoException(ManagedError managedError, string message = null, Exception exception = null) : base(message)
        {
            this.ManagedError = managedError;
            this.ManagedException = exception;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DevolutionsCryptoException"/> class.
        /// </summary>
        /// <param name="nativeError">The native error code.</param>
        /// <param name="message">The exception message. (Optional).</param>
        /// <param name="exception">The managed exception. (Optional).</param>
        public DevolutionsCryptoException(NativeError nativeError, string message = null, Exception exception = null) : base(message)
        {
            this.NativeError = nativeError;
            this.ManagedException = exception;
        }

        /// <summary>
        /// Gets or sets if not null, this describes the error that happenened on the managed side.
        /// </summary>
        public ManagedError? ManagedError { get; set; }

        /// <summary>
        /// Gets or sets if an unknown exception happens this property will contain it..
        /// </summary>
        public Exception ManagedException { get; set; }

        /// <summary>
        /// Gets override to add additionnal info in the exception message.
        /// </summary>
        public override string Message
        {
            get
            {
                return this.GetDetailedMessage() + "===Original Message===\r\n" + base.Message;
            }
        }

        /// <summary>
        /// Gets or sets if not null, this describes the error that happenened on the native side (Rust).
        /// </summary>
        public NativeError? NativeError { get; set; }

        /// <summary>
        /// Gets override to add additionnal info in the exception stacktrace.
        /// </summary>
        public override string StackTrace
        {
            get
            {
                return this.GetDetailedStackTrace() + "===Original StackTrace===\r\n" + base.StackTrace;
            }
        }

        /// <summary>
        /// The detailed message for the exception.
        /// </summary>
        /// <returns>The detailed message depending on the managed or native error.</returns>
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

        /// <summary>
        /// The Detailed stacktrace for the exception.
        /// </summary>
        /// <returns>The detailed stack trace depending on the managed or native error.</returns>
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