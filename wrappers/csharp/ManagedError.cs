using System;

namespace Devolutions.Cryptography
{
    public enum ManagedError
    {
        InvalidParameter,

        IncompatibleVersion,

        Error
    }

    public class DevolutionsCryptoException : Exception
    {        
        public DevolutionsCryptoException(ManagedError managedError, string message = null) : base(message)
        {
            this.ManagedError = managedError;
        }

        public DevolutionsCryptoException(NativeError nativeError, string message = null) : base(message)
        {
            this.NativeError = nativeError;
        }

        public NativeError? NativeError { get; set;}
        public ManagedError? ManagedError { get; set;}

        public override string Message
        {
            get
            {
                return this.GetDetailedError() + base.Message;
            }
        }

        public override string StackTrace 
        {
            get
            {
                return this.GetDetailedError() + base.StackTrace;
            }
        }

        public string GetDetailedError()
        {
            string result = string.Empty;

            if(this.NativeError != null)
            {
                result = "NativeError : " + this.NativeError.Value.ToString() + "\r\n";

                if(this.Data != null)
                {
                    this.Data["NativeError"] = this.NativeError.Value.ToString();
                }
            }

            if(this.ManagedError != null)
            {
                result = "ManagedError : " + this.ManagedError.Value.ToString() + "\r\n";

                if(this.Data != null)
                {
                    this.Data["ManagedError"] = this.ManagedError.Value.ToString();
                }
            }

            return result;
        }

        public override string ToString()
        {
            return this.GetDetailedError() + base.ToString();
        }
    }
}