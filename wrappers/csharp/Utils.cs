namespace Devolutions.Cryptography
{
    using System;
    using System.Text;
    
    public static partial class Utils
    {
        /// <summary>
        /// Validate that the base 64 string is from the Devolutions Crypto Library.
        /// Performance : Use ValidateSignature(byte[], DataType) for more performance if possible.
        /// </summary>
        /// <param name="data">The buffer to validate.</param>
        /// <param name="type">The data type to validate.</param>
        /// <returns>Returns true if the base 64 string received matches the data type.</returns>
        public static bool ValidateSignatureFromBase64(string base64, DataType type)
        {
            byte[] data = DecodeFromBase64(base64);

            return ValidateSignature(data, type);
        }

        /// <summary>
        /// Validate that the buffer is from the Devolutions Crypto Library.
        /// </summary>
        /// <param name="data">The buffer to validate.</param>
        /// <param name="type">The data type to validate.</param>
        /// <returns>Returns true if the buffer received matches the data type.</returns>
        public static bool ValidateSignature(byte[] data, DataType type)
        {
            if(data == null)
            {
                return false;
            }

            if(data.Length >= 8)
            {
                byte[] typeBytes = BitConverter.GetBytes((UInt16) type);
                if(!BitConverter.IsLittleEndian)
                {
                    Array.Reverse(typeBytes);
                }

                return data[0] == '\xD' && data[1] == '\xC' && data[2] == typeBytes[0] && data[3] == typeBytes[1];
            }

            return false;
        }

        /// <summary>
        /// Converts a string to a UTF8 encoded byte array.
        /// </summary>
        /// <param name="data">The string to convert.</param>
        /// <returns>A UTF8 string in a byte array.</returns>
        [Obsolete("This method has been deprecated. Use StringToUtf8ByteArray instead.")]
        public static byte[] StringToByteArray(string data)
        {
            return StringToUtf8ByteArray(data);
        }

        /// <summary>
        /// Converts a string to a UTF8 encoded byte array.
        /// </summary>
        /// <param name="data">The string to convert.</param>
        /// <returns>A UTF8 string in a byte array.</returns>
        public static byte[] StringToUtf8ByteArray(string data)
        {
            if (data == null)
            {
                return null;
            }

            return Encoding.UTF8.GetBytes(data);
        }

        /// <summary>
        /// Converts a byte array to a base 64 encoded string.
        /// </summary>
        /// <param name="bytes">The data to convert.</param>
        /// <returns>A base 64 string.</returns>
        [Obsolete("This method has been deprecated. Use EncodeToBase64 instead.")]
        public static string ToBase64String(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
            {
                return null;
            }

            return Encode(bytes);
        }

        /// <summary>
        /// Converts a base 64 string to a byte array.
        /// </summary>
        /// <param name="data">The data to convert.</param>
        /// <returns>A byte array.</returns>
        public static byte[] Base64StringToByteArray(string data)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

            return DecodeFromBase64(data);
        }

        /// <summary>
        /// Encode a byte array to a UTF8 encoded string.
        /// </summary>
        /// <param name="data">The data to convert.</param>
        /// <returns>A UTF8 encoded string.</returns>
        [Obsolete("This method has been deprecated. Use ByteArrayToUtf8String instead.")]
        public static string ByteArrayToString(byte[] data)
        {
            return ByteArrayToUtf8String(data);
        }

        /// <summary>
        /// Encode a byte array to a UTF8 encoded string.
        /// </summary>
        /// <param name="data">The data to convert.</param>
        /// <returns>A UTF8 encoded string.</returns>
        public static string ByteArrayToUtf8String(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

            try
            {
                return Encoding.UTF8.GetString(data);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Converts a base 64 string to a byte array.
        /// </summary>
        /// <param name="data">The data to convert.</param>
        /// <returns>A byte array.</returns>
        [Obsolete("This method has been deprecated. Use DecodeFromBase64 instead.")]
        public static byte[] Decode(string data)
        {
            return DecodeFromBase64(data);
        }

        /// <summary>
        /// Converts a base 64 string to a byte array.
        /// </summary>
        /// <param name="base64">The data to convert.</param>
        /// <returns>A byte array.</returns>
        public static byte[] DecodeFromBase64(string base64)
        {
            if (base64 == null || base64.Length == 0)
            {
                return null;
            }

            int length = GetDecodedLength(base64);

            if(length == 0)
            {
                return null;
            }

            byte[] buffer = new byte[length];

            long decode_res = Native.DecodeNative(base64, (UIntPtr)base64.Length, buffer, (UIntPtr)buffer.Length);

            if (decode_res == -1)
                return null;
            
            return buffer;
        }

        /// <summary>
        /// Converts a byte array to a base 64 encoded string.
        /// </summary>
        /// <param name="data">The data to convert.</param>
        /// <returns>A base 64 string.</returns>
        [Obsolete("This method has been deprecated. Use EncodeToBase64 instead.")]
        public static string Encode(byte[] data)
        {
            return EncodeToBase64String(data);
        }

        /// <summary>
        /// Converts a byte array to a base 64 encoded string.
        /// </summary>
        /// <param name="data">The data to convert.</param>
        /// <returns>A base 64 string.</returns>
        public static string EncodeToBase64String(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

            int length = GetEncodedLength(data);

            if(length == 0)
            {
                return null;
            }
            
            byte[] buffer = new byte[length];

            long encode_res = Native.EncodeNative(data, (UIntPtr)data.Length, buffer, (UIntPtr)buffer.Length);

            return ByteArrayToUtf8String(buffer);
        }

        /// <summary>
        /// Calculate the length of the resulting array if the buffer is encoded in base64.
        /// </summary>
        /// <param name="buffer">The buffer to calculate the resulting length.</param>
        /// <returns>The resulting base 64 buffer lentgh.</returns>
        public static int GetEncodedLength(byte[] buffer)
        {
            if(buffer == null)
            {
                return 0;
            }

            return ((4 * buffer.Length / 3) + 3) & ~3;
        }

        /// <summary>
        /// Calculate the length of the original buffer if the base 64 string is converted back.
        /// </summary>
        /// <param name="base64">The base 64 string to calculate the resulting length.</param>
        /// <returns>The original buffer length.</returns>
        public static int GetDecodedLength(string base64)
        {
            if (string.IsNullOrEmpty(base64)) 
            { 
                return 0; 
            }

            int characterCount = base64.Length;

            int result = Convert.ToInt32(3 * ((double)characterCount/4));
		
            int index = characterCount - 1;

            int loopCount = 1;

            while(base64[index] == '=' && loopCount <= 2)
            {
                result--;
                index--;
                loopCount++;
            }

            return  result;
        }

        /// <summary>
        /// Method used to throw the right exception depending on the error code.
        /// </summary>
        /// <param name="errorCode">The error code to handle.</param>
        public static void HandleError(long errorCode)
        {
            if (Enum.IsDefined(typeof(NativeError), (int)errorCode))
            {
                throw new DevolutionsCryptoException(((NativeError)errorCode));
            }
            else
            {
                throw new DevolutionsCryptoException(ManagedError.Error);
            }
        }

        /// <summary>
        /// Gets the native library version.
        /// </summary>
        /// <returns>Returns the native library version string.</returns>
        public static string Version()
        {
            long size = Native.VersionSizeNative();

            if(size < 0)
            {
                HandleError(size);
            }

            byte[] versionBytes = new byte[size];

            long res = Native.VersionNative(versionBytes, (UIntPtr)versionBytes.Length);

            if(res < 0)
            {
                HandleError(res);
            }  

            return Encoding.UTF8.GetString(versionBytes);
        }
    }
}