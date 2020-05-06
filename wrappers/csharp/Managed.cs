namespace Devolutions.Cryptography
{
    using System;
    using System.Runtime.InteropServices;

    using Devolutions.Cryptography.Argon2;

    public static class Managed
    {
#if RDM
        [System.Diagnostics.CodeAnalysis.SuppressMessage("StyleCop.CSharp.NamingRules", "SA1310:Field names should not contain underscore", Justification =
 "Preprocessor directive")]
        private const CipherVersion CIPHER_VERSION = CipherVersion.V1;
#else
        [System.Diagnostics.CodeAnalysis.SuppressMessage(
            "StyleCop.CSharp.NamingRules",
            "SA1310:Field names should not contain underscore",
            Justification = "Preprocessor directive")]
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
            if (password == null || password.Length == 0)
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

        /// <summary>
        /// Encrypts the data (which will be encoded into a UTF8 byte array) with the provided key.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="key">The key to use for encryption.</param>
        /// <param name="version">The cipher version to use. (Latest is recommended).</param>
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
        /// <param name="version">The cipher version to use. (Latest is recommended).</param>
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
        /// <param name="version">The cipher version to use. (Latest is recommended).</param>
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
        /// <param name="salt">The salt. (Optional).</param>
        /// <param name="iterations">The amount of iterations. 10 000 Recommended by NIST.</param>
        /// <param name="length">The resulting key length.</param>
        /// <returns>Returns the derived password.</returns>
        public static byte[] DeriveKey(byte[] key, byte[] salt = null, uint iterations = 10000, uint length = 32)
        {
            if (key == null || key.Length == 0)
            {
                throw new DevolutionsCryptoException(ManagedError.InvalidParameter);
            }

            byte[] result = new byte[length];

            int saltLength = salt?.Length ?? 0;

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
        /// <param name="salt">The salt. (Optional).</param>
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
        /// <param name="salt">The salt. (Optional).</param>
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
        /// <param name="version">The cipher version to use. (Latest is recommended).</param>
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
        /// <param name="version">The cipher version to use. (Latest is recommended).</param>
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
        /// <param name="version">The cipher version to use. (Latest is recommended).</param>
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
        /// <param name="cipher_version">The cipher version to use. (Latest is recommended).</param>
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
        /// <param name="cipher_version">The cipher version to use. (Latest is recommended).</param>
        /// <returns>Returns the encryption result as a base 64 encoded string.</returns>
        public static string EncryptWithPasswordAsBase64String(byte[] data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

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
        /// <param name="cipher_version">The cipher version to use. (Latest is recommended).</param>
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
        /// <param name="cipher_version">The cipher version to use. (Latest is recommended).</param>
        /// <returns>Returns the encryption result as a base 64 encoded string.</returns>
        public static string EncryptBase64WithPasswordAsBase64String(string b64data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION)
        {
            if (string.IsNullOrEmpty(b64data))
            {
                return null;
            }

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
        /// <param name="hash">The hash in bytes. Must be a hash from the method HashPassword().</param>
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
        /// <param name="version">The cipher version to use. (Latest is recommended).</param>
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
        /// <param name="version">The cipher version to use. (Latest is recommended).</param>
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
        /// <param name="cipher_version">The cipher version to use. (Latest is recommended).</param>
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
        /// <param name="cipher_version">The cipher version to use. (Latest is recommended).</param>
        /// <returns>Returns the encryption result as a base 64 encoded string.</returns>
        public static string EncryptWithPasswordAsBase64String(string data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION)
        {
            if (string.IsNullOrEmpty(data))
            {
                return null;
            }

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
        /// <param name="cipher_version">The cipher version to use. (Latest is recommended).</param>
        /// <returns>Returns the encryption result as a byte array.</returns>
        public static byte[] EncryptWithPassword(byte[] data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

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
        /// <param name="cipher_version">The cipher version to use. (Latest is recommended).</param>
        /// <returns>Returns the encryption result as a byte array.</returns>
        public static byte[] EncryptBase64WithPassword(string b64data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION)
        {
            if (string.IsNullOrEmpty(b64data))
            {
                return null;
            }

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
        /// <param name="cipher_version">The cipher version to use. (Latest is recommended).</param>
        /// <returns>Returns the encryption result as a byte array.</returns>
        public static byte[] EncryptWithPassword(string data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION)
        {
            if (string.IsNullOrEmpty(data))
            {
                return null;
            }

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
        /// <param name="password">The password to use for decryption.</param>
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
        /// <param name="password">The password to use for decryption.</param>
        /// <param name="iterations">The number of iterations used to derive the password.</param>
        /// <returns>Returns the decryption result as a UTF8 encoded string.</returns>
        public static string DecryptWithPasswordAsUtf8String(byte[] data, string password, uint iterations = 10000)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

            // There was a bug in DeriveKey v1 where the generated key was 256 bytes instead of 256 bits, only in C#.
            // This is unfortunatly the best way we found to fix it while keeping backward compatibility.
            // We try to decrypt with a 256 bits key, and if it doesn't work(InvalidMac means either the data or the key is invalid),
            //   we try with the buggy 256 bytes key.
            byte[] key = DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 32);

            if (key == null)
            {
                return null;
            }

            byte[] result = DecryptSafe(data, key, out DevolutionsCryptoException exception);

            if (exception != null && exception.NativeError == NativeError.InvalidMac)
            {
                key = null;
                result = null;

                key = DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 256);
                if (key == null)
                {
                    return null;
                }

                result = Decrypt(data, key);
                return Utils.ByteArrayToUtf8String(result);
            }
            else if (exception != null)
            {
                throw exception;
            }

            return Utils.ByteArrayToUtf8String(result);
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
        /// Join multiple shares to regenerate a shared secret.
        /// </summary>
        /// <param name="shares">This is a 2-dimensional array representing the shares.</param>
        /// <returns>The output buffer with the shared secret.</returns>
        public static byte[] JoinShares(byte[][] shares)
        {
            if (!SharesLengthAreValid(shares))
            {
                throw new DevolutionsCryptoException(ManagedError.InvalidParameter);
            }

#pragma warning disable CA1062 // null-check is already done in SharesLengthAreValid
            int nbShares = shares.Length;
#pragma warning restore CA1062 // null-check is already done in SharesLengthAreValid

            int sharesLength = shares[0].Length;
            int secretLength = (int)Native.JoinSharesSizeNative((UIntPtr)sharesLength);

            byte[] secret = new byte[secretLength];

            // Get unmanaged references
            GCHandle[] handles = new GCHandle[(int)nbShares];
            for (int i = 0; i < shares.Length; i++)
            {
                handles[i] = GCHandle.Alloc(shares[i], GCHandleType.Pinned);
            }

            IntPtr[] pointers = new IntPtr[(int)nbShares];
            for (int i = 0; i < handles.Length; i++)
            {
                pointers[i] = handles[i].AddrOfPinnedObject();
            }

            // Call the native method
            long result = Native.JoinSharesNative((UIntPtr)nbShares, (UIntPtr)sharesLength, pointers, secret, (UIntPtr)secretLength);

            // Free the pointers
            for (int i = 0; i < handles.Length; i++)
            {
                handles[i].Free();
            }

            // Handle errors
            if (result < 0)
            {
                Utils.HandleError(result);
            }

            return secret;
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
            if (string.IsNullOrEmpty(b64data))
            {
                return null;
            }

            // There was a bug in DeriveKey v1 where the generated key was 256 bytes instead of 256 bits, only in C#.
            // This is unfortunatly the best way we found to fix it while keeping backward compatibility.
            // We try to decrypt with a 256 bits key, and if it doesn't work(InvalidMac means either the data or the key is invalid),
            //   we try with the buggy 256 bytes key.
            byte[] key = DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 32);

            if (key == null)
            {
                return null;
            }

            byte[] result = DecryptSafe(Utils.Base64StringToByteArray(b64data), key, out DevolutionsCryptoException exception);

            if (exception != null && exception.NativeError == NativeError.InvalidMac)
            {
                key = null;
                result = null;

                key = DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 256);

                if (key == null)
                {
                    return null;
                }

                result = Decrypt(Utils.Base64StringToByteArray(b64data), key);
            }
            else if (exception != null)
            {
                throw exception;
            }

            return Utils.ByteArrayToUtf8String(result);
        }

        public static byte[][] GenerateSharedKey(int nbShares, int threshold, int secretLength)
        {
            int sharesLength = (int)Native.GenerateSharedKeySizeNative((UIntPtr)secretLength);

            byte[][] shares = new byte[nbShares][];

            for (int i = 0; i < nbShares; i++)
            {
                shares[i] = new byte[sharesLength];
            }

            GCHandle[] handles = new GCHandle[(int)nbShares];
            for (int i = 0; i < shares.Length; i++)
            {
                handles[i] = GCHandle.Alloc(shares[i], GCHandleType.Pinned);
            }

            IntPtr[] pointers = new IntPtr[(int)nbShares];
            for (int i = 0; i < handles.Length; i++)
            {
                pointers[i] = handles[i].AddrOfPinnedObject();
            }

            long result = Native.GenerateSharedKeyNative((UIntPtr)nbShares, (UIntPtr)threshold, (UIntPtr)secretLength, pointers);
            for (int i = 0; i < handles.Length; i++)
            {
                handles[i].Free();
            }

            // Handle errors
            if (result < 0)
            {
                Utils.HandleError(result);
            }

            return shares;
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
            if (data == null || data.Length == 0)
            {
                return null;
            }

            //// There was a bug in DeriveKey v1 where the generated key was 256 bytes instead of 256 bits, only in C#.
            //// This is unfortunatly the best way we found to fix it while keeping backward compatibility.
            //// We try to decrypt with a 256 bits key, and if it doesn't work(InvalidMac means either the data or the key is invalid),
            ////   we try with the buggy 256 bytes key.
            byte[] key = DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 32);

            if (key == null)
            {
                return null;
            }

            byte[] result = DecryptSafe(data, key, out DevolutionsCryptoException exception);

            if (exception != null && exception.NativeError == NativeError.InvalidMac)
            {
                key = null;
                result = null;

                key = DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 256);

                if (key == null)
                {
                    return null;
                }

                result = Decrypt(data, key);
            }
            else if (exception != null)
            {
                throw exception;
            }

            return result;
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
            if (string.IsNullOrEmpty(b64data))
            {
                return null;
            }

            // There was a bug in DeriveKey v1 where the generated key was 256 bytes instead of 256 bits, only in C#.
            // This is unfortunatly the best way we found to fix it while keeping backward compatibility.
            // We try to decrypt with a 256 bits key, and if it doesn't work(InvalidMac means either the data or the key is invalid),
            //   we try with the buggy 256 bytes key.
            byte[] key = DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 32);

            if (key == null)
            {
                return null;
            }

            byte[] result = DecryptSafe(Utils.Base64StringToByteArray(b64data), key, out DevolutionsCryptoException exception);

            if (exception != null && exception.NativeError == NativeError.InvalidMac)
            {
                key = null;
                result = null;

                key = DeriveKey(Utils.StringToUtf8ByteArray(password), null, iterations, 256);

                if (key == null)
                {
                    return null;
                }

                result = Decrypt(Utils.Base64StringToByteArray(b64data), key);
            }
            else if (exception != null)
            {
                throw exception;
            }

            return result;
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

        /// <summary>
        /// Decrypts the data with the provided key. No exceptions are thrown in case of failure.
        /// </summary>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="key">The key to use for decryption.</param>
        /// <param name="exception">The exception if an error occurs.</param>
        /// <returns>Returns the decryption result in a byte array.</returns>
        internal static byte[] DecryptSafe(byte[] data, byte[] key, out DevolutionsCryptoException exception)
        {
            exception = null;

            if (data == null || data.Length == 0)
            {
                return null;
            }

            if (key == null)
            {
                exception = new DevolutionsCryptoException(ManagedError.InvalidParameter);

                return null;
            }

            byte[] result = new byte[data.Length];
            long res = Native.DecryptNative(data, (UIntPtr)data.Length, key, (UIntPtr)key.Length, result, (UIntPtr)result.Length);

            if (res < 0)
            {
                exception = Utils.GetDevolutionsCryptoException(res);
                return null;
            }

            // If success it returns the real result size, so we resize.
            Array.Resize(ref result, (int)res);

            return result;
        }

        private static bool SharesLengthAreValid(byte[][] shares)
        {
            if (shares == null || shares.Length == 0)
            {
                return false;
            }

            int len = shares[0].Length;
            bool lengthIsValid = true;

            for (int j = 1; j < shares.Length; j++)
            {
                if (shares[j].Length != len)
                {
                    lengthIsValid = false;
                    break;
                }
            }

            return lengthIsValid;
        }
    }
}