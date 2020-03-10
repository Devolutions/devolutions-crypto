namespace Devolutions.Cryptography
{
    using System;

    using Devolutions.Cryptography.Argon2;

    public static class Managed
    {
#if RDM
        private const CipherVersion CIPHER_VERSION = CipherVersion.V1;
#else
        private const CipherVersion CIPHER_VERSION = CipherVersion.Latest;
#endif
        /// <summary>
        /// Performs a key exchange.
        /// </summary>
        /// <param name="privateKey">The private key to mix.</param>
        /// <param name="publicKey">The public key.</param>
        /// <returns>Returns the resulting shared key.</returns>
        public static byte[] MixKeyExchange(byte[] privateKey, byte[] publicKey)
        {
            if (publicKey == null || privateKey == null)
            {
                throw new DevolutionsCryptoException(ManagedError.InvalidParameter);
            }

            long sharedKeySize = Native.MixKeyExchangeSizeNative();

            if (sharedKeySize < 0)
            {
                Utils.HandleError(sharedKeySize);
            }

            byte[] shared = new byte[sharedKeySize];

            long res = Native.MixKeyExchangeNative(privateKey, (UIntPtr)privateKey.Length, publicKey, (UIntPtr)publicKey.Length, shared, (UIntPtr)shared.Length);

            if (res < 0)
            {
                Utils.HandleError(res);
            }

            return shared;
        }

        /// <summary>
        /// Get the default argon2 parameters.
        /// </summary>
        /// <returns>Returns the default argon2 parameters.</returns>
        public static Argon2Parameters GetDefaultArgon2Parameters()
        {
            long size = Native.GetDefaultArgon2ParametersSizeNative();

            if (size < 0)
            {
                Utils.HandleError(size);
            }

            byte[] rawParameters = new byte[size];

            long res = Native.GetDefaultArgon2ParametersNative(rawParameters, (UIntPtr)size);

            if (res < 0)
            {
                Utils.HandleError(res);
            }

            return Argon2Parameters.FromByteArray(rawParameters);
        }

        /// <summary>
        /// Generates a key pair from a password.
        /// </summary>
        /// <param name="password">The password to use for the derivation.</param>
        /// <param name="parameters">The argon2 parameters to use.</param>
        /// <returns>Returns a keypair.</returns>
        public static KeyPair DeriveKeyPair(byte[] password, Argon2Parameters parameters)
        {
            if (password == null)
            {
                return null;
            }

            if (parameters == null)
            {
                throw new DevolutionsCryptoException(ManagedError.InvalidParameter);
            }

            long size = Native.DeriveKeyPairSizeNative();

            if (size < 0)
            {
                Utils.HandleError(size);
            }

            byte[] parameters_raw = parameters.ToByteArray();

            byte[] privateKey = new byte[size];

            byte[] publicKey = new byte[size];

            long res = Native.DeriveKeyPairNative(
                password,
                (UIntPtr)password.Length,
                parameters_raw,
                (UIntPtr)parameters_raw.Length,
                privateKey,
                (UIntPtr)privateKey.Length,
                publicKey,
                (UIntPtr)publicKey.Length);

            if (res < 0)
            {
                Utils.HandleError(res);
            }

            return new KeyPair()
                {
                    PrivateKey = privateKey,
                    PublicKey = publicKey
                };
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
            byte[] cipher = Encrypt(Utils.StringToUtf8ByteArray(data), key, version);

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
            byte[] cipher = Encrypt(Utils.StringToUtf8ByteArray(data), key, version);

            return cipher;
        }

        /// <summary>
        /// Derives the password using PBKDF2.
        /// </summary>
        /// <param name="key">The password to derive.</param>
        /// <param name="salt">The salt. (Optional)</param>
        /// <param name="iterations">The amount of iterations. 10 000 Recommended by NIST.</param>
        /// <param name="length">The resulting key length.</param>
        /// <returns>Returns the derived password.</returns>
        public static byte[] DeriveKey(byte[] key, byte[] salt = null, uint iterations = 10000, uint length = 32)
        {
            if (key == null)
            {
                throw new DevolutionsCryptoException(ManagedError.InvalidParameter);
            }

            byte[] result = new byte[length];

            int saltLength = salt == null ? 0 : salt.Length;

            long res = Native.DeriveKeyNative(key, (UIntPtr)key.Length, salt, (UIntPtr)saltLength, (UIntPtr)iterations, result, (UIntPtr)result.Length);

            if (res < 0)
            {
                Utils.HandleError(res);
            }

            return result;
        }

        /// <summary>
        /// Derives the password string (which will be encoded into a UTF8 byte array) using PBKDF2.
        /// </summary>
        /// <param name="password">The password to derive.</param>
        /// <param name="salt">The salt. (Optional)</param>
        /// <param name="iterations">The amount of iterations. 10 000 Recommended by NIST.</param>
        /// <param name="length">The resulting key length.</param>
        /// <returns>Returns the derived password.</returns>
        public static byte[] DerivePassword(string password, byte[] salt = null, uint iterations = 10000, uint length = 32)
        {
            return DeriveKey(Utils.StringToUtf8ByteArray(password), salt, iterations, length);
        }

        /// <summary>
        /// Derives a password with the parameters provided.
        /// </summary>
        /// <param name="password">The data to decrypt.</param>
        /// <param name="salt">The salt. (Optional)</param>
        /// <param name="iterations">The amount of iterations. 10 000 Recommended by NIST.</param>
        /// <returns>Returns the decryption result in a byte array.</returns>
        public static byte[] DerivePassword(string password, string salt, uint iterations = 10000)
        {
            return DeriveKey(Utils.StringToUtf8ByteArray(password), Utils.StringToUtf8ByteArray(salt), iterations);
        }

        /// <summary>
        /// Decrypts the data with the provided key.
        /// </summary>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="key">The key to use for decryption.</param>
        /// <returns>Returns the decryption result in a byte array.</returns>
        public static byte[] Decrypt(byte[] data, byte[] key)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

            if (key == null)
            {
                throw new DevolutionsCryptoException(ManagedError.InvalidParameter);
            }

            byte[] result = new byte[data.Length];

            long res = Native.DecryptNative(data, (UIntPtr)data.Length, key, (UIntPtr)key.Length, result, (UIntPtr)result.Length);

            if (res < 0)
            {
                Utils.HandleError(res);
            }

            // If success it returns the real result size, so we resize. 
            Array.Resize(ref result, (int)res);

            return result;
        }

        /// <summary>
        /// Decrypts the data with the provided private key.
        /// </summary>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="privateKey">The private key to use for decryption.</param>
        /// <returns>Returns the decryption result in a byte array.</returns>
        public static byte[] DecryptAsymmetric(byte[] data, byte[] privateKey)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

            if (privateKey == null)
            {
                throw new DevolutionsCryptoException(ManagedError.InvalidParameter);
            }

            byte[] result = new byte[data.Length];

            long res = Native.DecryptAsymmetricNative(data, (UIntPtr)data.Length, privateKey, (UIntPtr)privateKey.Length, result, (UIntPtr)result.Length);

            if (res < 0)
            {
                Utils.HandleError(res);
            }

            // If success it returns the real result size, so we resize. 
            Array.Resize(ref result, (int)res);

            return result;
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
            byte[] cipher = Encrypt(data, key, version);

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
            byte[] cipher = Encrypt(data, key, version);

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
            if (cipher_version == CipherVersion.V1 || cipher_version == CipherVersion.V2)
            {
                keySize = 256;
            }
            else
            {
                keySize = 32;
            }

            byte[] key = DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, keySize);

            byte[] cipher = Encrypt(data, key, cipher_version);

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
            if (cipher_version == CipherVersion.V1 || cipher_version == CipherVersion.V2)
            {
                keySize = 256;
            }
            else
            {
                keySize = 32;
            }

            byte[] key = DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, keySize);

            byte[] cipher = Encrypt(Utils.Base64StringToByteArray(b64data), key, cipher_version);

            return Utils.EncodeToBase64String(cipher);
        }

        /// <summary>
        /// Generates a random key.
        /// </summary>
        /// <param name="keySize">The length of the key desired.</param>
        /// <returns>Returns a random key.</returns>
        public static byte[] GenerateKey(uint keySize)
        {
            if (keySize == 0)
            {
                throw new DevolutionsCryptoException(ManagedError.InvalidParameter);
            }

            byte[] key = new byte[keySize];

            long res = Native.GenerateKeyNative(key, (UIntPtr)keySize);

            if (res < 0)
            {
                Utils.HandleError(res);
            }

            return key;
        }

        /// <summary>
        /// Verify if the password matches the hash.
        /// </summary>
        /// <param name="password">The password in bytes.</param>
        /// <param name="hash">The hash in bytes. Must be a hash from the method HashPassword() </param>
        /// <returns>Returns true if the password matches with the hash.</returns>
        public static bool VerifyPassword(byte[] password, byte[] hash)
        {
            if (password == null || hash == null)
            {
                throw new DevolutionsCryptoException(ManagedError.InvalidParameter);
            }

            long res = Native.VerifyPasswordNative(password, (UIntPtr)password.Length, hash, (UIntPtr)hash.Length);

            if (res == 0)
            {
                return false;
            }

            if (res < 0)
            {
                Utils.HandleError(res);
            }

            return true;
        }

        /// <summary>
        /// Hash a password.
        /// </summary>
        /// <param name="password">The password to hash in bytes.</param>
        /// <param name="iterations">The number of iterations used to hash the password. 10 000 Recommended by NIST.</param>
        /// <returns>Returns the hashed password in bytes.</returns>
        public static byte[] HashPassword(byte[] password, uint iterations = 10000)
        {
            if (password == null || password.Length == 0)
            {
                throw new DevolutionsCryptoException(ManagedError.InvalidParameter);
            }

            long hashLength = Native.HashPasswordLengthNative();

            if (hashLength < 0)
            {
                Utils.HandleError(hashLength);
            }

            byte[] result = new byte[hashLength];

            long res = Native.HashPasswordNative(password, (UIntPtr)password.Length, iterations, result, (UIntPtr)result.Length);

            if (res < 0)
            {
                Utils.HandleError(res);
            }

            return result;
        }

        /// <summary>
        /// Generates a pair of random public and private keys.
        /// </summary>
        /// <returns>Returns the random public and private keys.</returns>
        public static KeyPair GenerateKeyPair()
        {
            long keySize = Native.GenerateKeyPairSizeNative();

            byte[] publicKey = new byte[keySize];
            byte[] privateKey = new byte[keySize];

            long res = Native.GenerateKeyPairNative(privateKey, (UIntPtr)privateKey.Length, publicKey, (UIntPtr)publicKey.Length);

            if (res < 0)
            {
                Utils.HandleError(res);
            }

            return new KeyPair()
                {
                    PublicKey = publicKey,
                    PrivateKey = privateKey
                };
        }

        /// <summary>
        /// Encrypts the data.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="key">The key to use for encryption.</param>
        /// <param name="version">The cipher version to use. (Latest is recommended)</param>
        /// <returns>Returns the encryption result as byte array.</returns>
        public static byte[] Encrypt(byte[] data, byte[] key, CipherVersion version = CIPHER_VERSION)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

            if (key == null)
            {
                throw new DevolutionsCryptoException(ManagedError.InvalidParameter);
            }

            long resultLength = Native.EncryptSizeNative((UIntPtr)data.Length, (ushort)version);

            if (resultLength < 0)
            {
                Utils.HandleError(resultLength);
            }

            byte[] result = new byte[resultLength];

            long res = Native.EncryptNative(data, (UIntPtr)data.Length, key, (UIntPtr)key.Length, result, (UIntPtr)result.Length, (ushort)version);

            if (res < 0)
            {
                Utils.HandleError(res);
            }

            return result;
        }

        /// <summary>
        /// Encrypts the data using asymmetric encryption.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="publicKey">The public key to use for encryption.</param>
        /// <param name="version">The cipher version to use. (Latest is recommended)</param>
        /// <returns>Returns the encryption result as byte array.</returns>
        public static byte[] EncryptAsymmetric(byte[] data, byte[] publicKey, CipherVersion version = CIPHER_VERSION)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

            if (publicKey == null)
            {
                throw new DevolutionsCryptoException(ManagedError.InvalidParameter);
            }

            long resultLength = Native.EncryptAsymmetricSizeNative((UIntPtr)data.Length, (ushort)version);

            if (resultLength < 0)
            {
                Utils.HandleError(resultLength);
            }

            byte[] result = new byte[resultLength];

            long res = Native.EncryptAsymmetricNative(data, (UIntPtr)data.Length, publicKey, (UIntPtr)publicKey.Length, result, (UIntPtr)result.Length, (ushort)version);

            if (res < 0)
            {
                Utils.HandleError(res);
            }

            return result;
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
            if (cipher_version == CipherVersion.V1 || cipher_version == CipherVersion.V2)
            {
                keySize = 256;
            }
            else
            {
                keySize = 32;
            }

            byte[] key = DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, keySize);

            byte[] cipher = Encrypt(Utils.StringToUtf8ByteArray(data), key, cipher_version);

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
            if (cipher_version == CipherVersion.V1 || cipher_version == CipherVersion.V2)
            {
                keySize = 256;
            }
            else
            {
                keySize = 32;
            }

            byte[] key = DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, keySize);

            byte[] cipher = Encrypt(data, key, cipher_version);

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
            if (cipher_version == CipherVersion.V1 || cipher_version == CipherVersion.V2)
            {
                keySize = 256;
            }
            else
            {
                keySize = 32;
            }

            byte[] key = DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, keySize);

            byte[] cipher = Encrypt(Utils.Base64StringToByteArray(b64data), key, cipher_version);

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
            if (cipher_version == CipherVersion.V1 || cipher_version == CipherVersion.V2)
            {
                keySize = 256;
            }
            else
            {
                keySize = 32;
            }

            byte[] key = DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, keySize);

            byte[] cipher = Encrypt(Utils.StringToUtf8ByteArray(data), key, cipher_version);

            return cipher;
        }

        /***************************************************************
         * 
         *                       Decrypt
         * 
         * **************************************************************/

        /// <summary>
        /// Decrypts the base64 string with the provided key.
        /// </summary>
        /// <param name="b64data">The base 64 string to decrypt.</param>
        /// <param name="key">The key to use for decryption.</param>
        /// <returns>Returns the decryption result as a UTF8 encoded string.</returns>
        [Obsolete("This method has been deprecated. Use DecryptWithKeyAsUtf8String instead.")]
        public static string DecryptWithKeyAsString(string b64data, byte[] key)
        {
            return DecryptWithKeyAsUtf8String(b64data, key);
        }

        /// <summary>
        /// Decrypts the base64 string with the provided key.
        /// </summary>
        /// <param name="b64data">The base 64 string to decrypt.</param>
        /// <param name="key">The key to use for decryption.</param>
        /// <returns>Returns the decryption result as a UTF8 encoded string.</returns>
        public static string DecryptWithKeyAsUtf8String(string b64data, byte[] key)
        {
            byte[] result = Decrypt(Utils.Base64StringToByteArray(b64data), key);

            return Utils.ByteArrayToUtf8String(result);
        }

        /// <summary>
        /// Decrypts the base64 string with the provided key.
        /// </summary>
        /// <param name="b64data">The base 64 string to decrypt.</param>
        /// <param name="key">The key to use for decryption.</param>
        /// <returns>Returns the decryption result as a byte array.</returns>
        public static byte[] DecryptWithKey(string b64data, byte[] key)
        {
            byte[] result = Decrypt(Utils.Base64StringToByteArray(b64data), key);

            return result;
        }

        /// <summary>
        /// Decrypts the data with the provided key.
        /// </summary>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="key">The key to use for decryption.</param>
        /// <returns>Returns the decryption result as a UTF8 encoded string.</returns>
        [Obsolete("This method has been deprecated. Use DecryptWithKeyAsUtf8String instead.")]
        public static string DecryptWithKeyAsString(byte[] data, byte[] key)
        {
            return DecryptWithKeyAsUtf8String(data, key);
        }

        /// <summary>
        /// Decrypts the data with the provided key.
        /// </summary>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="key">The key to use for decryption.</param>
        /// <returns>Returns the decryption result as a UTF8 encoded string.</returns>
        public static string DecryptWithKeyAsUtf8String(byte[] data, byte[] key)
        {
            byte[] result = Decrypt(data, key);

            return Utils.ByteArrayToUtf8String(result);
        }

        /// <summary>
        /// Decrypts the data with the provided key.
        /// </summary>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="key">The key to use for decryption.</param>
        /// <returns>Returns the decryption result as a byte array.</returns>
        public static byte[] DecryptWithKey(byte[] data, byte[] key)
        {
            byte[] result = Decrypt(data, key);

            return result;
        }

        /// <summary>
        /// Decrypts the data with the provided password (which will be encoded into a UTF8 byte array and derived).
        /// </summary>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="key">The key to use for decryption.</param>
        /// <param name="iterations">The number of iterations used to derive the password.</param>
        /// <returns>Returns the decryption result as a UTF8 encoded string.</returns>
        [Obsolete("This method has been deprecated. Use DecryptWithPasswordAsUtf8String instead.")]
        public static string DecryptWithPasswordAsString(byte[] data, string password, uint iterations = 10000)
        {
            return DecryptWithPasswordAsUtf8String(data, password, iterations);
        }

        /// <summary>
        /// Decrypts the data with the provided password (which will be encoded into a UTF8 byte array and derived).
        /// </summary>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="key">The key to use for decryption.</param>
        /// <param name="iterations">The number of iterations used to derive the password.</param>
        /// <returns>Returns the decryption result as a UTF8 encoded string.</returns>
        public static string DecryptWithPasswordAsUtf8String(byte[] data, string password, uint iterations = 10000)
        {
            // There was a bug in DeriveKey v1 where the generated key was 256 bytes instead of 256 bits, only in C#. 
            // This is unfortunatly the best way we found to fix it while keeping backward compatibility.
            // We try to decrypt with a 256 bits key, and if it doesn't work(InvalidMac means either the data or the key is invalid),
            //   we try with the buggy 256 bytes key.
            try
            {
                byte[] key = DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 32);

                if (key == null)
                {
                    return null;
                }

                byte[] result = Decrypt(data, key);

                return Utils.ByteArrayToUtf8String(result);
            }
            catch (DevolutionsCryptoException ex)
            {
                if (ex.NativeError == NativeError.InvalidMac)
                {
                    byte[] key = DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 256);
                    if (key == null)
                    {
                        return null;
                    }

                    byte[] result = Decrypt(data, key);
                    return Utils.ByteArrayToUtf8String(result);
                }
                else
                {
                    throw ex;
                }
            }
        }

        /// <summary>
        /// Decrypts the base 64 data (which will be decoded to the original data) with the provided password (which will be encoded into a UTF8 byte array and derived).
        /// </summary>
        /// <param name="b64data">The data to decrypt.</param>
        /// <param name="password">The password to use for decryption.</param>
        /// <param name="iterations">The number of iterations used to derive the password.</param>
        /// <returns>Returns the decryption result as a UTF8 encoded string.</returns>
        [Obsolete("This method has been deprecated. Use DecryptWithPasswordAsUtf8String instead.")]
        public static string DecryptWithPasswordAsString(string b64data, string password, uint iterations = 10000)
        {
            return DecryptWithPasswordAsUtf8String(b64data, password, iterations);
        }

        /// <summary>
        /// Decrypts the base 64 data (which will be decoded to the original data) with the provided password (which will be encoded into a UTF8 byte array and derived).
        /// </summary>
        /// <param name="b64data">The data to decrypt.</param>
        /// <param name="password">The password to use for decryption.</param>
        /// <param name="iterations">The number of iterations used to derive the password.</param>
        /// <returns>Returns the decryption result as a UTF8 encoded string.</returns>
        public static string DecryptWithPasswordAsUtf8String(string b64data, string password, uint iterations = 10000)
        {
            // There was a bug in DeriveKey v1 where the generated key was 256 bytes instead of 256 bits, only in C#. 
            // This is unfortunatly the best way we found to fix it while keeping backward compatibility.
            // We try to decrypt with a 256 bits key, and if it doesn't work(InvalidMac means either the data or the key is invalid),
            //   we try with the buggy 256 bytes key.
            try
            {
                byte[] key = DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 32);

                if (key == null)
                {
                    return null;
                }

                byte[] result = Decrypt(Utils.Base64StringToByteArray(b64data), key);

                return Utils.ByteArrayToUtf8String(result);
            }
            catch (DevolutionsCryptoException ex)
            {
                if (ex.NativeError == NativeError.InvalidMac)
                {
                    byte[] key = DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 256);

                    if (key == null)
                    {
                        return null;
                    }

                    byte[] result = Decrypt(Utils.Base64StringToByteArray(b64data), key);

                    return Utils.ByteArrayToUtf8String(result);
                }
                else
                {
                    throw ex;
                }
            }
        }

        /// <summary>
        /// Decrypts the data with the provided password (which will be encoded into a UTF8 byte array and derived).
        /// </summary>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="password">The password to use for decryption.</param>
        /// <param name="iterations">The number of iterations used to derive the password.</param>
        /// <returns>Returns the decryption result as a byte array.</returns>
        public static byte[] DecryptWithPassword(byte[] data, string password, uint iterations = 10000)
        {
            // There was a bug in DeriveKey v1 where the generated key was 256 bytes instead of 256 bits, only in C#. 
            // This is unfortunatly the best way we found to fix it while keeping backward compatibility.
            // We try to decrypt with a 256 bits key, and if it doesn't work(InvalidMac means either the data or the key is invalid),
            //   we try with the buggy 256 bytes key.
            try
            {
                byte[] key = DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 32);

                if (key == null)
                {
                    return null;
                }

                byte[] result = Decrypt(data, key);

                return result;
            }
            catch (DevolutionsCryptoException ex)
            {
                if (ex.NativeError == NativeError.InvalidMac)
                {
                    byte[] key = DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 256);

                    if (key == null)
                    {
                        return null;
                    }

                    byte[] result = Decrypt(data, key);

                    return result;
                }
                else
                {
                    throw ex;
                }
            }
        }

        /// <summary>
        /// Decrypts the base 64 data (which will be decoded to the original data) with the provided password (which will be encoded into a UTF8 byte array and derived).
        /// </summary>
        /// <param name="b64data">The data to decrypt.</param>
        /// <param name="password">The password to use for decryption.</param>
        /// <param name="iterations">The number of iterations used to derive the password.</param>
        /// <returns>Returns the decryption result as a byte array.</returns>
        public static byte[] DecryptWithPassword(string b64data, string password, uint iterations = 10000)
        {
            // There was a bug in DeriveKey v1 where the generated key was 256 bytes instead of 256 bits, only in C#. 
            // This is unfortunatly the best way we found to fix it while keeping backward compatibility.
            // We try to decrypt with a 256 bits key, and if it doesn't work(InvalidMac means either the data or the key is invalid),
            //   we try with the buggy 256 bytes key.
            try
            {
                byte[] key = DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 32);

                if (key == null)
                {
                    return null;
                }

                byte[] result = Decrypt(Utils.Base64StringToByteArray(b64data), key);

                return result;
            }
            catch (DevolutionsCryptoException ex)
            {
                if (ex.NativeError == NativeError.InvalidMac)
                {
                    byte[] key = DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 256);

                    if (key == null)
                    {
                        return null;
                    }

                    byte[] result = Decrypt(Utils.Base64StringToByteArray(b64data), key);

                    return result;
                }
                else
                {
                    throw ex;
                }
            }
        }

        [Obsolete("This method has been deprecated. Use Managed.GenerateKey instead.")]
        public static Guid GenerateAPIKey()
        {
            byte[] apiKey = GenerateKey(16);

            if (apiKey == null)
            {
                return Guid.Empty;
            }

            return new Guid(apiKey);
        }
    }
}