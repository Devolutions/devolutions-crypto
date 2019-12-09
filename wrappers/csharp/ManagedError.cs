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

        public override string ToString()
        {
            string result = string.Empty;

            if(this.NativeError != null)
            {
                result = "NativeError : " + this.NativeError.Value.ToString() + "\r\n";
            }

            if(this.ManagedError != null)
            {
                result = "ManagedError : " + this.ManagedError.Value.ToString() + "\r\n";
            }

            return result + base.ToString();
        }
    }
}