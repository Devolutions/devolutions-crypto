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

        public static byte[] DeriveKey(byte[] password, byte[] salt = null, uint iterations = 10000, uint length = 32)
        {
            return Native.DeriveKey(password, salt, iterations, length);
        }

        public static byte[] DeriveKey(string password, byte[] salt = null, uint iterations = 10000, uint length = 32)
        {
            return Native.DeriveKey(Utils.StringToByteArray(password), salt, iterations, length);
        }

        public static byte[] GenerateKey(uint keySize)
        {
            return Native.GenerateKey(keySize);
        }

        /***************************************************************
         * 
         *                       Encrypt
         * 
         * **************************************************************/

        public static string EncryptWithKeyAsString(string data, byte[] key, CipherVersion version = CIPHER_VERSION)
        {
            byte[] cipher = Native.Encrypt(Utils.StringToByteArray(data), key, (uint)version);

            return Utils.ToBase64String(cipher);
        }

        public static byte[] EncryptWithKey(string data, byte[] key, CipherVersion version = CIPHER_VERSION)
        {
            byte[] cipher = Native.Encrypt(Utils.StringToByteArray(data), key, (uint)version);

            return cipher;
        }

        public static string EncryptWithKeyAsString(byte[] data, byte[] key, CipherVersion version = CIPHER_VERSION)
        {
            byte[] cipher = Native.Encrypt(data, key, (uint)version);

            return Utils.ToBase64String(cipher);
        }

        public static byte[] EncryptWithKey(byte[] data, byte[] key, CipherVersion version = CIPHER_VERSION)
        {
            byte[] cipher = Native.Encrypt(data, key, (uint)version);

            return cipher;
        }

        public static string EncryptWithPasswordAsString(byte[] data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION)
        {
            uint keySize;
            if(cipher_version == CipherVersion.V2_5) {
                keySize = 32;
            }
            else {
                keySize = 256;
            }

            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, keySize);

            byte[] cipher = Native.Encrypt(data, key, (uint)cipher_version);

            return Utils.ToBase64String(cipher);
        }

        // Encrypt base64 string data and return base64 string
        public static string EncryptBase64WithPasswordAsString(string b64data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION)
        {
            uint keySize;
            if(cipher_version == CipherVersion.V2_5) {
                keySize = 32;
            }
            else {
                keySize = 256;
            }

            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, keySize);

            byte[] cipher = Native.Encrypt(Utils.Base64StringToByteArray(b64data), key, (uint)cipher_version);

            return Utils.ToBase64String(cipher);
        }

        public static string EncryptWithPasswordAsString(string data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION)
        {
            uint keySize;
            if(cipher_version == CipherVersion.V2_5) {
                keySize = 32;
            }
            else {
                keySize = 256;
            }

            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, keySize);

            byte[] cipher = Native.Encrypt(Utils.StringToByteArray(data), key, (uint)cipher_version);

            return Utils.ToBase64String(cipher);
        }
        

        public static byte[] EncryptWithPassword(byte[] data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION)
        {
            uint keySize;
            if(cipher_version == CipherVersion.V2_5) {
                keySize = 32;
            }
            else {
                keySize = 256;
            }

            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, keySize);

            byte[] cipher = Native.Encrypt(data, key, (uint)cipher_version);

            return cipher;
        }

        // Encrypt base64 string data
        public static byte[] EncryptBase64WithPassword(string b64data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION)
        {
            uint keySize;
            if(cipher_version == CipherVersion.V2_5) {
                keySize = 32;
            }
            else {
                keySize = 256;
            }

            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, keySize);

            byte[] cipher = Native.Encrypt(Utils.Base64StringToByteArray(b64data), key, (uint)cipher_version);

            return cipher;
        }

        public static byte[] EncryptWithPassword(string data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION)
        {
            uint keySize;
            if(cipher_version == CipherVersion.V2_5) {
                keySize = 32;
            }
            else {
                keySize = 256;
            }

            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, keySize);

            byte[] cipher = Native.Encrypt(Utils.StringToByteArray(data), key, (uint)cipher_version);

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

            return Utils.ByteArrayToString(result);
        }

        public static byte[] DecryptWithKey(string data, byte[] key, uint iterations = 10000)
        {
            byte[] result = Native.Decrypt(Utils.Base64StringToByteArray(data), key);

            return result;
        }

        public static string DecryptWithKeyAsString(byte[] data, byte[] key, uint iterations = 10000)
        {
            byte[] result = Native.Decrypt(data, key);

            return Utils.ByteArrayToString(result);
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
                byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, 32);

                if(key == null)
                {
                    return null;
                }

                byte[] result = Native.Decrypt(data, key);

                return Utils.ByteArrayToString(result);
            }
            catch(DevolutionsCryptoException ex) {
                if(ex.NativeError == NativeError.InvalidMac) {
                    byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, 256);
                    if(key == null)
                    {
                        return null;
                    }

                    byte[] result = Native.Decrypt(data, key);
                    return Utils.ByteArrayToString(result);
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
                byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, 32);

                if(key == null)
                {
                    return null;
                }

                byte[] result = Native.Decrypt(Utils.Base64StringToByteArray(data), key);

                return Utils.ByteArrayToString(result);
            }
            catch(DevolutionsCryptoException ex) {
                if(ex.NativeError == NativeError.InvalidMac) {
                    byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, 256);

                    if(key == null)
                    {
                        return null;
                    }

                    byte[] result = Native.Decrypt(Utils.Base64StringToByteArray(data), key);

                    return Utils.ByteArrayToString(result);
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
                byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, 32);

                if(key == null)
                {
                    return null;
                }

                byte[] result = Native.Decrypt(data, key);

                return result;
            }
            catch(DevolutionsCryptoException ex) {
                if(ex.NativeError == NativeError.InvalidMac) {
                    byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, 256);

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
                byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, 32);

                if(key == null)
                {
                    return null;
                }

                byte[] result = Native.Decrypt(Utils.Base64StringToByteArray(data), key);

                return result;
            }
            catch(DevolutionsCryptoException ex) {
                if(ex.NativeError == NativeError.InvalidMac) {
                    byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, 256);

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