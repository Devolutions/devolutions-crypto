namespace Devolutions.Cryptography
{
    using System;
    using System.IO;
    using System.Text;

    /// <summary>
    /// Useful functions from Devolutions Crypto
    /// </summary>
    public static class Utils
    {
        /// <summary>
        /// Converts a base 64 string to a byte array.
        /// </summary>
        /// <param name="data">The data to convert.</param>
        /// <returns>A byte array.</returns>
        public static byte[] Base64StringToByteArray(string data)
        {
            if (string.IsNullOrEmpty(data))
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
            catch (DecoderFallbackException)
            {
                return null;
            }
        }

        /// <summary>
        /// Concatenate arrays together.
        /// </summary>
        /// <param name="list">List of arrays to concatenate.</param>
        /// <returns>Returns the arrays concatenated into a single array. </returns>
        public static byte[] ConcatArrays(params byte[][] list)
        {
            int length = 0;

            for (int i = 0; i < list.Length; i++)
            {
                length += list[i].Length;
            }

            byte[] result = new byte[length];
            int offset = 0;

            for (int x = 0; x < list.Length; x++)
            {
                list[x].CopyTo(result, offset);
                offset += list[x].Length;
            }

            return result;
        }

        /// <summary>
        /// Compare two strings with constant-time equality.
        /// </summary>
        /// <param name="x">The first value to compare.</param>
        /// <param name="y">The second value to compare.</param>
        /// <returns>Returns false if the values are not equal is invalid or true if the values are equal. If there is an error,
        ///     it will trigger a DevolutionsCryptoException.</returns>
        public static bool ConstantTimeEquals(string x, string y)
        {
            if (x == null)
            {
                x = string.Empty;
            }

            if (y == null)
            {
                y = string.Empty;
            }

            byte[] xBytes = Encoding.UTF8.GetBytes(x);
            byte[] yBytes = Encoding.UTF8.GetBytes(y);

            return ConstantTimeEquals(xBytes, yBytes);
        }

        /// <summary>
        /// Compare two guids with constant-time equality.
        /// </summary>
        /// <param name="x">The first value to compare.</param>
        /// <param name="y">The second value to compare.</param>
        /// <returns>Returns false if the values are not equal is invalid or true if the values are equal. If there is an error,
        ///     it will trigger a DevolutionsCryptoException.</returns>
        public static bool ConstantTimeEquals(Guid x, Guid y)
        {
            byte[] xBytes = x.ToByteArray();
            byte[] yBytes = y.ToByteArray();

            return ConstantTimeEquals(xBytes, yBytes);
        }

        /// <summary>
        /// Compare two byte arrays with constant-time equality.
        /// </summary>
        /// <param name="x">The first value to compare.</param>
        /// <param name="y">The second value to compare.</param>
        /// <returns>Returns false if the values are not equal is invalid or true if the values are equal. If there is an error,
        ///     it will trigger a DevolutionsCryptoException.</returns>
        public static bool ConstantTimeEquals(byte[] x, byte[] y)
        {
            if (x == null || y == null)
            {
                return x == null && y == null;
            }

            long res = Native.ConstantTimeEquals(x, (UIntPtr)x.Length, y, (UIntPtr)y.Length);

            if (res < 0)
            {
                throw GetDevolutionsCryptoException(res);
            }

            return res == 1;
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
            if (string.IsNullOrEmpty(base64))
            {
                return null;
            }

            int length = GetDecodedBase64StringLength(base64);

            if (length == 0)
            {
                return null;
            }

            byte[] buffer = new byte[length];

            long decode_res = Native.DecodeNative(base64, (UIntPtr)base64.Length, buffer, (UIntPtr)buffer.Length);

            if (decode_res == -1)
            {
                return null;
            }

            return buffer;
        }

        /// <summary>
        /// Converts a base 64 url string to a byte array.
        /// </summary>
        /// <param name="base64url">The data to convert.</param>
        /// <returns>A byte array.</returns>
        public static byte[] DecodeFromBase64Url(string base64url)
        {
            if (string.IsNullOrEmpty(base64url))
            {
                return null;
            }

            byte[] buffer = new byte[base64url.Length];

            long decode_res = Native.DecodeUrlNative(base64url, (UIntPtr)base64url.Length, buffer, (UIntPtr)buffer.Length);

            if (decode_res == -1)
            {
                return null;
            }

            Array.Resize(ref buffer, (int)decode_res);

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

            int length = GetEncodedBase64StringLength(data);

            if (length == 0)
            {
                return null;
            }

            byte[] buffer = new byte[length];

            long encode_res = Native.EncodeNative(data, (UIntPtr)data.Length, buffer, (UIntPtr)buffer.Length);

            return ByteArrayToUtf8String(buffer);
        }

        /// <summary>
        /// Converts a byte array to a base 64 url encoded string.
        /// </summary>
        /// <param name="data">The data to convert.</param>
        /// <returns>A base 64 url string.</returns>
        public static string EncodeToBase64UrlString(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

            int length = (data.Length * 4 / 3) + 4;

            byte[] buffer = new byte[length];

            long encode_res = Native.EncodeUrlNative(data, (UIntPtr)data.Length, buffer, (UIntPtr)buffer.Length);

            Array.Resize(ref buffer, (int)encode_res);

            return ByteArrayToUtf8String(buffer);
        }

        /// <summary>
        /// Calculate the length of the original buffer if the base 64 string is converted back.
        /// Warning this method doesn't validate if the string is valid base64.
        /// </summary>
        /// <param name="base64">The base 64 string to calculate the resulting length.</param>
        /// <returns>The original buffer length.</returns>
        public static int GetDecodedBase64StringLength(string base64)
        {
            if (string.IsNullOrEmpty(base64) || base64.Length % 4 != 0)
            {
                return 0;
            }

            int padCount = 0;

            for (int i = base64.Length - 1; i >= base64.Length - 2; i--)
            {
                if (base64[i] == '=')
                {
                    padCount++;
                }
            }

            return (3 * (base64.Length / 4)) - padCount;
        }

        /// <summary>
        /// Calculate the length of the original buffer if the base 64 string is converted back.
        /// Warning this method doesn't validate if the string is valid base64.
        /// </summary>
        /// <param name="base64">The base 64 string to calculate the resulting length.</param>
        /// <returns>The original buffer length.</returns>
        [Obsolete("This method has been deprecated. Use GetDecodedBase64StringLength instead.")]
        public static int GetDecodedLength(string base64)
        {
            return GetDecodedBase64StringLength(base64);
        }

        /// <summary>
        /// Calculate the length of the resulting array if the buffer is encoded in base64.
        /// </summary>
        /// <param name="buffer">The buffer to calculate the resulting length.</param>
        /// <returns>The resulting base 64 buffer lentgh.</returns>
        public static int GetEncodedBase64StringLength(byte[] buffer)
        {
            if (buffer == null)
            {
                return 0;
            }

            return ((4 * buffer.Length / 3) + 3) & ~3;
        }

        /// <summary>
        /// Calculate the length of the resulting array if the buffer is encoded in base64.
        /// </summary>
        /// <param name="buffer">The buffer to calculate the resulting length.</param>
        /// <returns>The resulting base 64 buffer lentgh.</returns>
        [Obsolete("This method has been deprecated. Use GetEncodedBase64StringLength instead.")]
        public static int GetEncodedLength(byte[] buffer)
        {
            return GetEncodedBase64StringLength(buffer);
        }

        /// <summary>
        /// This method is exposed for a very specific use case. Do not rely on it.
        /// </summary>
        /// <returns>The resulting hash.</returns>
        public static string ScryptSimple(byte[] password, byte[] salt, byte logN, uint r, uint p)
        {
            if (password == null || salt == null)
            {
                throw new DevolutionsCryptoException(ManagedError.InvalidParameter);
            }

            long length = (int)Native.ScryptSimpleSize();

            byte[] hash = new byte[length];

            long res = Native.ScryptSimple(password, (UIntPtr)password.Length, salt, (UIntPtr)salt.Length, logN, r, p, hash, (UIntPtr)hash.Length);

            if (res < 0)
            {
                HandleError(res);
            }

            Array.Resize(ref hash, (int)res);

            return ByteArrayToUtf8String(hash);
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
        /// Validate that the buffer is from the Devolutions Crypto Library.
        /// </summary>
        /// <param name="data">The buffer to validate.</param>
        /// <param name="type">The data type to validate.</param>
        /// <returns>Returns true if the buffer received matches the data type.</returns>
        public static bool ValidateHeader(byte[] data, DataType type)
        {
            if (data == null)
            {
                return false;
            }

            long result = Native.ValidateHeader(data, (UIntPtr)data.Length, (ushort)type);

            if (result < 0)
            {
                HandleError(result);
            }

            return Convert.ToBoolean(result);
        }

        /// <summary>
        /// Validate that the base 64 string is from the Devolutions Crypto Library.
        /// Performance : Use ValidateHeader(byte[], DataType) for more performance if possible.
        /// </summary>
        /// <param name="base64">The buffer to validate.</param>
        /// <param name="type">The data type to validate.</param>
        /// <returns>Returns true if the base 64 string received matches the data type.</returns>
        public static bool ValidateHeaderFromBase64(string base64, DataType type)
        {
            byte[] data = DecodeFromBase64(base64);

            return ValidateHeader(data, type);
        }

        /// <summary>
        /// Validate that the stream data is from the Devolutions Crypto Library.
        /// The stream must support both Seeking and Reading.
        /// Performance : Use ValidateHeader(byte[], DataType) for more performance if possible.
        /// </summary>
        /// <param name="stream">The stream to validate.</param>
        /// <param name="type">The data type to validate.</param>
        /// <returns>Returns true if the stream data received matches the data type.</returns>
        public static bool ValidateHeaderFromStream(Stream stream, DataType type)
        {
            if (stream == null)
            {
                return false;
            }

            try
            {
                if (!stream.CanSeek)
                {
                    throw new DevolutionsCryptoException(ManagedError.CanNotSeekStream);
                }

                if (!stream.CanRead)
                {
                    throw new DevolutionsCryptoException(ManagedError.CanNotReadStream);
                }

                long originalPosition = stream.Position;

                byte[] buffer = new byte[8];

                int count = stream.Read(buffer, 0, 8);

                stream.Position = originalPosition;

                if (count < 8)
                {
                    return false;
                }

                return ValidateHeader(buffer, type);
            }
            catch (DevolutionsCryptoException)
            {
                throw;
            }
            catch (Exception ex)
            {
                DevolutionsCryptoException exception = new DevolutionsCryptoException(ManagedError.Error, exception: ex);
                throw exception;
            }
        }

        /// <summary>
        /// Validate that the buffer is from the Devolutions Crypto Library.
        /// </summary>
        /// <param name="data">The buffer to validate.</param>
        /// <param name="type">The data type to validate.</param>
        /// <returns>Returns true if the buffer received matches the data type.</returns>
        [Obsolete("This method has been deprecated. Use ValidateHeader instead.")]
        public static bool ValidateSignature(byte[] data, DataType type)
        {
            return ValidateHeader(data, type);
        }

        /// <summary>
        /// Validate that the base 64 string is from the Devolutions Crypto Library.
        /// Performance : Use ValidateHeader(byte[], DataType) for more performance if possible.
        /// </summary>
        /// <param name="base64">The buffer to validate.</param>
        /// <param name="type">The data type to validate.</param>
        /// <returns>Returns true if the base 64 string received matches the data type.</returns>
        [Obsolete("This method has been deprecated. Use ValidateHeaderFromBase64 instead.")]
        public static bool ValidateSignatureFromBase64(string base64, DataType type)
        {
            return ValidateHeaderFromBase64(base64, type);
        }

        /// <summary>
        /// Validate that the stream data is from the Devolutions Crypto Library.
        /// The stream must support both Seeking and Reading.
        /// Performance : Use ValidateHeader(byte[], DataType) for more performance if possible.
        /// </summary>
        /// <param name="stream">The stream to validate.</param>
        /// <param name="type">The data type to validate.</param>
        /// <returns>Returns true if the stream data received matches the data type.</returns>
        [Obsolete("This method has been deprecated. Use ValidateHeaderFromStream instead.")]
        public static bool ValidateSignatureFromStream(Stream stream, DataType type)
        {
            return ValidateHeaderFromStream(stream, type);
        }

        /// <summary>
        /// Gets the native library version.
        /// </summary>
        /// <returns>Returns the native library version string.</returns>
        public static string Version()
        {
            long size = Native.VersionSizeNative();

            if (size < 0)
            {
                HandleError(size);
            }

            byte[] versionBytes = new byte[size];

            long res = Native.VersionNative(versionBytes, (UIntPtr)versionBytes.Length);

            if (res < 0)
            {
                HandleError(res);
            }

            return Encoding.UTF8.GetString(versionBytes);
        }

        /// <summary>
        /// Method used to return the right exception depending on the error code.
        /// </summary>
        /// <param name="errorCode">The error code to handle.</param>
        /// <returns>The exception matching the error code.</returns>
        internal static DevolutionsCryptoException GetDevolutionsCryptoException(long errorCode)
        {
            if (Enum.IsDefined(typeof(NativeError), (int)errorCode))
            {
                return new DevolutionsCryptoException((NativeError)errorCode);
            }

            return new DevolutionsCryptoException(ManagedError.Error);
        }

        /// <summary>
        /// Method used to throw the right exception depending on the error code.
        /// </summary>
        /// <param name="errorCode">The error code to handle.</param>
        internal static void HandleError(long errorCode)
        {
            if (Enum.IsDefined(typeof(NativeError), (int)errorCode))
            {
                throw new DevolutionsCryptoException((NativeError)errorCode);
            }
            else
            {
                throw new DevolutionsCryptoException(ManagedError.Error);
            }
        }
    }
}