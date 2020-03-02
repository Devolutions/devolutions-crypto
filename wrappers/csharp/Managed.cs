namespace Devolutions.Cryptography
{
    using System;
    using System.Text;

    public static class Managed
    {
#if RDM
        private const CipherVersion CIPHER_VERSION = CipherVersion.V1;
#else
        private const CipherVersion CIPHER_VERSION = CipherVersion.Latest;
#endif
        /// <summary>
        /// Derives the password using PBKDF2.
        /// </summary>
        /// <param name="password">The password to derive.</param>
        /// <param name="salt">The salt. (Optional)</param>
        /// <param name="iterations">The amount of iterations. 10 000 Recommended by NIST.</param>
        /// <param name="length">The resulting key length.</param>
        /// <returns>Returns the derived password.</returns>
        public static byte[] DeriveKey(byte[] password, byte[] salt = null, uint iterations = 10000, uint length = 32)
        {
            return Native.DeriveKey(password, salt, iterations, length);
        }

        /// <summary>
        /// Derives the password string (which will be encoded into a UTF8 byte array) using PBKDF2.
        /// </summary>
        /// <param name="password">The password to derive.</param>
        /// <param name="salt">The salt. (Optional)</param>
        /// <param name="iterations">The amount of iterations. 10 000 Recommended by NIST.</param>
        /// <param name="length">The resulting key length.</param>
        /// <returns>Returns the derived password.</returns>
        public static byte[] DeriveKey(string password, byte[] salt = null, uint iterations = 10000, uint length = 32)
        {
            return Native.DeriveKey(Utils.StringToUtf8ByteArray(password), salt, iterations, length);
        }

        /// <summary>
        /// Generates a random key.
        /// </summary>
        /// <param name="keySize">The length of the key desired.</param>
        /// <returns>Returns a random key.</returns>
        public static byte[] GenerateKey(uint keySize)
        {
            return Native.GenerateKey(keySize);
        }

        /***************************************************************
         * 
         *                       Encrypt
         * 
         * **************************************************************/

        /// <summary>
        /// Encrypts the data (which will be encoded into a UTF8 byte array) with the provided key.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="key">The key to use for encryption.</param>
        /// <param name="version">The cipher version to use. (Latest is recommended)</param>
        /// <returns>Returns the encryption result as a base 64 encoded string.</returns>
        [Obsolete("This method has been deprecated. Use EncryptWithKeyAsBase64String instead.")]
        public static string EncryptWithKeyAsString(string data, byte[] key, CipherVersion version = CIPHER_VERSION)
        {
            return EncryptWithKeyAsBase64String(data, key, version);
        }

        /// <summary>
        /// Encrypts the data (which will be encoded into a UTF8 byte array) with the provided key.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="key">The key to use for encryption.</param>
        /// <param name="version">The cipher version to use. (Latest is recommended)</param>
        /// <returns>Returns the encryption result as a base 64 encoded string.</returns>
        public static string EncryptWithKeyAsBase64String(string data, byte[] key, CipherVersion version = CIPHER_VERSION)
        {
            byte[] cipher = Native.Encrypt(Utils.StringToUtf8ByteArray(data), key, (uint)version);

            return Utils.EncodeToBase64String(cipher);
        }

        /// <summary>
        /// Encrypts the data (which will be encoded into a UTF8 byte array) with the provided key.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="key">The key to use for encryption.</param>
        /// <param name="version">The cipher version to use. (Latest is recommended)</param>
        /// <returns>Returns the encryption result as a byte array.</returns>
        public static byte[] EncryptWithKey(string data, byte[] key, CipherVersion version = CIPHER_VERSION)
        {
            byte[] cipher = Native.Encrypt(Utils.StringToUtf8ByteArray(data), key, (uint)version);

            return cipher;
        }

        /// <summary>
        /// Encrypts the data with the provided key.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="key">The key to use for encryption.</param>
        /// <param name="version">The cipher version to use. (Latest is recommended)</param>
        /// <returns>Returns the encryption result as a base 64 encoded string.</returns>
        [Obsolete("This method has been deprecated. Use EncryptWithKeyAsBase64String instead.")]
        public static string EncryptWithKeyAsString(byte[] data, byte[] key, CipherVersion version = CIPHER_VERSION)
        {
            return EncryptWithKeyAsBase64String(data, key, version);
        }

        /// <summary>
        /// Encrypts the data with the provided key.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="key">The key to use for encryption.</param>
        /// <param name="version">The cipher version to use. (Latest is recommended)</param>
        /// <returns>Returns the encryption result as a base 64 encoded string.</returns>
        public static string EncryptWithKeyAsBase64String(byte[] data, byte[] key, CipherVersion version = CIPHER_VERSION)
        {
            byte[] cipher = Native.Encrypt(data, key, (uint)version);

            return Utils.EncodeToBase64String(cipher);
        }

        /// <summary>
        /// Encrypts the data with the provided key.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="key">The key to use for encryption.</param>
        /// <param name="version">The cipher version to use. (Latest is recommended)</param>
        /// <returns>Returns the encryption result as a byte array.</returns>
        public static byte[] EncryptWithKey(byte[] data, byte[] key, CipherVersion version = CIPHER_VERSION)
        {
            byte[] cipher = Native.Encrypt(data, key, (uint)version);

            return cipher;
        }

        /// <summary>
        /// Encrypts the data with the provided password (which will be encoded into a UTF8 byte array and derived).
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="password">The password to use for encryption.</param>
        /// <param name="iterations">The number of iterations used to derive the password. 10 000 Recommended by NIST.</param>
        /// <param name="cipher_version">The cipher version to use. (Latest is recommended)</param>
        /// <returns>Returns the encryption result as a base 64 encoded string.</returns>
        [Obsolete("This method has been deprecated. Use EncryptWithPasswordAsBase64String instead.")]
        public static string EncryptWithPasswordAsString(byte[] data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION)
        {
            return EncryptWithPasswordAsBase64String(data, password, iterations, cipher_version);
        }

        /// <summary>
        /// Encrypts the data with the provided password (which will be encoded into a UTF8 byte array and derived).
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="password">The password to use for encryption.</param>
        /// <param name="iterations">The number of iterations used to derive the password. 10 000 Recommended by NIST.</param>
        /// <param name="cipher_version">The cipher version to use. (Latest is recommended)</param>
        /// <returns>Returns the encryption result as a base 64 encoded string.</returns>
        public static string EncryptWithPasswordAsBase64String(byte[] data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION)
        {
            uint keySize;
            if(cipher_version == CipherVersion.V1 || cipher_version == CipherVersion.V2) {
                keySize = 256;
            }
            else {
                keySize = 32;
            }

            byte[] key = Native.DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, keySize);

            byte[] cipher = Native.Encrypt(data, key, (uint)cipher_version);

            return Utils.EncodeToBase64String(cipher);
        }

        /// <summary>
        /// Encrypts the base 64 string (which will be decoded to the original data) with the provided password (which will be encoded into a UTF8 byte array and derived).
        /// </summary>
        /// <param name="b64data">The data to encrypt.</param>
        /// <param name="password">The password to use for encryption.</param>
        /// <param name="iterations">The number of iterations used to derive the password. 10 000 Recommended by NIST.</param>
        /// <param name="cipher_version">The cipher version to use. (Latest is recommended)</param>
        /// <returns>Returns the encryption result as a base 64 encoded string.</returns>
        public static string EncryptBase64WithPasswordAsString(string b64data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION)
        {
            return EncryptBase64WithPasswordAsBase64String(b64data, password, iterations, cipher_version);
        }

        /// <summary>
        /// Encrypts the base 64 string (which will be decoded to the original data) with the provided password (which will be encoded into a UTF8 byte array and derived).
        /// </summary>
        /// <param name="b64data">The data to encrypt.</param>
        /// <param name="password">The password to use for encryption.</param>
        /// <param name="iterations">The number of iterations used to derive the password. 10 000 Recommended by NIST.</param>
        /// <param name="cipher_version">The cipher version to use. (Latest is recommended)</param>
        /// <returns>Returns the encryption result as a base 64 encoded string.</returns>
        public static string EncryptBase64WithPasswordAsBase64String(string b64data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION)
        {
            uint keySize;
            if(cipher_version == CipherVersion.V1 || cipher_version == CipherVersion.V2) {
                keySize = 256;
            }
            else {
                keySize = 32;
            }

            byte[] key = Native.DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, keySize);

            byte[] cipher = Native.Encrypt(Utils.Base64StringToByteArray(b64data), key, (uint)cipher_version);

            return Utils.EncodeToBase64String(cipher);
        }

        /// <summary>
        /// Encrypts the data (which will be encoded into a UTF8 byte array) with the provided password (which will be encoded into a UTF8 byte array and derived).
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="password">The password to use for encryption.</param>
        /// <param name="iterations">The number of iterations used to derive the password. 10 000 Recommended by NIST.</param>
        /// <param name="cipher_version">The cipher version to use. (Latest is recommended)</param>
        /// <returns>Returns the encryption result as a base 64 encoded string.</returns>
        [Obsolete("This method has been deprecated. Use EncryptWithPasswordAsBase64String instead.")]
        public static string EncryptWithPasswordAsString(string data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION)
        {
            return EncryptWithPasswordAsBase64String(data, password, iterations, cipher_version);
        }

        /// <summary>
        /// Encrypts the data (which will be encoded into a UTF8 byte array) with the provided password (which will be encoded into a UTF8 byte array and derived).
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="password">The password to use for encryption.</param>
        /// <param name="iterations">The number of iterations used to derive the password. 10 000 Recommended by NIST.</param>
        /// <param name="cipher_version">The cipher version to use. (Latest is recommended)</param>
        /// <returns>Returns the encryption result as a base 64 encoded string.</returns>
        public static string EncryptWithPasswordAsBase64String(string data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION)
        {
            uint keySize;
            if(cipher_version == CipherVersion.V1 || cipher_version == CipherVersion.V2) {
                keySize = 256;
            }
            else {
                keySize = 32;
            }

            byte[] key = Native.DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, keySize);

            byte[] cipher = Native.Encrypt(Utils.StringToUtf8ByteArray(data), key, (uint)cipher_version);

            return Utils.EncodeToBase64String(cipher);
        }
        

        /// <summary>
        /// Encrypts the data with the provided password (which will be encoded into a UTF8 byte array and derived).
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="password">The password to use for encryption.</param>
        /// <param name="iterations">The number of iterations used to derive the password. 10 000 Recommended by NIST.</param>
        /// <param name="cipher_version">The cipher version to use. (Latest is recommended)</param>
        /// <returns>Returns the encryption result as a byte array.</returns>
        public static byte[] EncryptWithPassword(byte[] data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION)
        {
            uint keySize;
            if(cipher_version == CipherVersion.V1 || cipher_version == CipherVersion.V2) {
                keySize = 256;
            }
            else {
                keySize = 32;
            }

            byte[] key = Native.DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, keySize);

            byte[] cipher = Native.Encrypt(data, key, (uint)cipher_version);

            return cipher;
        }

        /// <summary>
        /// Encrypts the base 64 string (which will be decoded to the original data) with the provided password (which will be encoded into a UTF8 byte array and derived).
        /// </summary>
        /// <param name="b64data">The data to encrypt.</param>
        /// <param name="password">The password to use for encryption.</param>
        /// <param name="iterations">The number of iterations used to derive the password. 10 000 Recommended by NIST.</param>
        /// <param name="cipher_version">The cipher version to use. (Latest is recommended)</param>
        /// <returns>Returns the encryption result as a byte array.</returns>
        public static byte[] EncryptBase64WithPassword(string b64data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION)
        {
            uint keySize;
            if(cipher_version == CipherVersion.V1 || cipher_version == CipherVersion.V2) {
                keySize = 256;
            }
            else {
                keySize = 32;
            }

            byte[] key = Native.DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, keySize);

            byte[] cipher = Native.Encrypt(Utils.Base64StringToByteArray(b64data), key, (uint)cipher_version);

            return cipher;
        }

        /// <summary>
        /// Encrypts the data (which will be encoded into a UTF8 byte array) with the provided password (which will be encoded into a UTF8 byte array and derived).
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="password">The password to use for encryption.</param>
        /// <param name="iterations">The number of iterations used to derive the password. 10 000 Recommended by NIST.</param>
        /// <param name="cipher_version">The cipher version to use. (Latest is recommended)</param>
        /// <returns>Returns the encryption result as a byte array.</returns>
        public static byte[] EncryptWithPassword(string data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION)
        {
            uint keySize;
            if(cipher_version == CipherVersion.V1 || cipher_version == CipherVersion.V2) {
                keySize = 256;
            }
            else {
                keySize = 32;
            }

            byte[] key = Native.DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, keySize);

            byte[] cipher = Native.Encrypt(Utils.StringToUtf8ByteArray(data), key, (uint)cipher_version);

            return cipher;
        }


        /***************************************************************
         * 
         *                       Decrypt
         * 
         * **************************************************************/
        
        public static string DecryptWithKeyAsString(string data, byte[] key, uint iterations = 10000)
        {
            byte[] result = Native.Decrypt(Utils.Base64StringToByteArray(data), key);

            return Utils.ByteArrayToUtf8String(result);
        }

        public static byte[] DecryptWithKey(string data, byte[] key, uint iterations = 10000)
        {
            byte[] result = Native.Decrypt(Utils.Base64StringToByteArray(data), key);

            return result;
        }

        public static string DecryptWithKeyAsString(byte[] data, byte[] key, uint iterations = 10000)
        {
            byte[] result = Native.Decrypt(data, key);

            return Utils.ByteArrayToUtf8String(result);
        }

        public static byte[] DecryptWithKey(byte[] data, byte[] key, uint iterations = 10000)
        {
            byte[] result = Native.Decrypt(data, key);

            return result;
        }

        public static string DecryptWithPasswordAsString(byte[] data, string password, uint iterations = 10000)
        {
            // There was a bug in DeriveKey v1 where the generated key was 256 bytes instead of 256 bits, only in C#. 
            // This is unfortunatly the best way we found to fix it while keeping backward compatibility.
            // We try to decrypt with a 256 bits key, and if it doesn't work(InvalidMac means either the data or the key is invalid),
            //   we try with the buggy 256 bytes key.
            try {
                byte[] key = Native.DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 32);

                if(key == null)
                {
                    return null;
                }

                byte[] result = Native.Decrypt(data, key);

                return Utils.ByteArrayToUtf8String(result);
            }
            catch(DevolutionsCryptoException ex) {
                if(ex.NativeError == NativeError.InvalidMac) {
                    byte[] key = Native.DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 256);
                    if(key == null)
                    {
                        return null;
                    }

                    byte[] result = Native.Decrypt(data, key);
                    return Utils.ByteArrayToUtf8String(result);
                }
                else {
                    throw ex;
                }
            }
        }

        // Encrypt base64 string data and return base64 string
        public static string DecryptWithPasswordAsString(string data, string password, uint iterations = 10000)
        {
            // There was a bug in DeriveKey v1 where the generated key was 256 bytes instead of 256 bits, only in C#. 
            // This is unfortunatly the best way we found to fix it while keeping backward compatibility.
            // We try to decrypt with a 256 bits key, and if it doesn't work(InvalidMac means either the data or the key is invalid),
            //   we try with the buggy 256 bytes key.
            try {
                byte[] key = Native.DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 32);

                if(key == null)
                {
                    return null;
                }

                byte[] result = Native.Decrypt(Utils.Base64StringToByteArray(data), key);

                return Utils.ByteArrayToUtf8String(result);
            }
            catch(DevolutionsCryptoException ex) {
                if(ex.NativeError == NativeError.InvalidMac) {
                    byte[] key = Native.DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 256);

                    if(key == null)
                    {
                        return null;
                    }

                    byte[] result = Native.Decrypt(Utils.Base64StringToByteArray(data), key);

                    return Utils.ByteArrayToUtf8String(result);
                }
                else {
                    throw ex;
                }
            }
        }


        public static byte[] DecryptWithPassword(byte[] data, string password, uint iterations = 10000)
        {
            // There was a bug in DeriveKey v1 where the generated key was 256 bytes instead of 256 bits, only in C#. 
            // This is unfortunatly the best way we found to fix it while keeping backward compatibility.
            // We try to decrypt with a 256 bits key, and if it doesn't work(InvalidMac means either the data or the key is invalid),
            //   we try with the buggy 256 bytes key.
            try {
                byte[] key = Native.DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 32);

                if(key == null)
                {
                    return null;
                }

                byte[] result = Native.Decrypt(data, key);

                return result;
            }
            catch(DevolutionsCryptoException ex) {
                if(ex.NativeError == NativeError.InvalidMac) {
                    byte[] key = Native.DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 256);

                    if(key == null)
                    {
                        return null;
                    }

                    byte[] result = Native.Decrypt(data, key);

                    return result;
                }
                else {
                    throw ex;
                }
            }
        }

        // Encrypt base64 string data and return base64 string
        public static byte[] DecryptWithPassword(string data, string password, uint iterations = 10000)
        {
            // There was a bug in DeriveKey v1 where the generated key was 256 bytes instead of 256 bits, only in C#. 
            // This is unfortunatly the best way we found to fix it while keeping backward compatibility.
            // We try to decrypt with a 256 bits key, and if it doesn't work(InvalidMac means either the data or the key is invalid),
            //   we try with the buggy 256 bytes key.
            try {
                byte[] key = Native.DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 32);

                if(key == null)
                {
                    return null;
                }

                byte[] result = Native.Decrypt(Utils.Base64StringToByteArray(data), key);

                return result;
            }
            catch(DevolutionsCryptoException ex) {
                if(ex.NativeError == NativeError.InvalidMac) {
                    byte[] key = Native.DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 256);

                    if(key == null)
                    {
                        return null;
                    }

                    byte[] result = Native.Decrypt(Utils.Base64StringToByteArray(data), key);

                    return result;
                }
                else {
                    throw ex;
                }
            }
        }

        public static Guid GenerateAPIKey()
        {
            byte[] apiKey = Native.GenerateKey(16);

            if (apiKey == null)
            {
                return Guid.Empty;
            }

            return new Guid(apiKey);
        }
    }   
}