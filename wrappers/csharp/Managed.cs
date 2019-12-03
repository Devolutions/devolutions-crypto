namespace Devolutions.Cryptography
{
    using System;
    using System.Text;

    public static class Managed
    {
#if RDM
        private const CipherVersion CIPHER_VERSION = CipherVersion.Aes256CbcHmacSha256;
#else
        private const CipherVersion CIPHER_VERSION = CipherVersion.Latest;
#endif

        public static byte[] DeriveKey(byte[] password, byte[] salt = null, uint iterations = 10000, Action<Enum> error = null)
        {
            return Native.DeriveKey(password, salt, iterations, error);
        }

        public static byte[] DeriveKey(string password, byte[] salt = null, uint iterations = 10000, Action<Enum> error = null)
        {
            return Native.DeriveKey(Utils.StringToByteArray(password), salt, iterations, error);
        }

        public static byte[] GenerateKey(uint keySize, Action<Enum> error = null)
        {
            return Native.GenerateKey(keySize, error);
        }

        /***************************************************************
         * 
         *                       Encrypt
         * 
         * **************************************************************/

        public static string EncryptWithKeyAsString(string data, byte[] key, CipherVersion version = CIPHER_VERSION, Action<Enum> error = null)
        {
            byte[] cipher = Native.Encrypt(Utils.StringToByteArray(data), key, (uint)version, error);

            return Utils.ToBase64String(cipher);
        }

        public static byte[] EncryptWithKey(string data, byte[] key, CipherVersion version = CIPHER_VERSION, Action<Enum> error = null)
        {
            byte[] cipher = Native.Encrypt(Utils.StringToByteArray(data), key, (uint)version, error);

            return cipher;
        }

        public static string EncryptWithKeyAsString(byte[] data, byte[] key, CipherVersion version = CIPHER_VERSION, Action<Enum> error = null)
        {
            byte[] cipher = Native.Encrypt(data, key, (uint)version, error);

            return Utils.ToBase64String(cipher);
        }

        public static byte[] EncryptWithKey(byte[] data, byte[] key, CipherVersion version = CIPHER_VERSION, Action<Enum> error = null)
        {
            byte[] cipher = Native.Encrypt(data, key, (uint)version, error);

            return cipher;
        }

        public static string EncryptWithPasswordAsString(byte[] data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION, Action<Enum> error = null)
        {
            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, error);

            byte[] cipher = Native.Encrypt(data, key, (uint)cipher_version, error);

            return Utils.ToBase64String(cipher);
        }

        // Encrypt base64 string data and return base64 string
        public static string EncryptBase64WithPasswordAsString(string b64data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION, Action<Enum> error = null)
        {
            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, error);

            byte[] cipher = Native.Encrypt(Utils.Base64StringToByteArray(b64data), key, (uint)cipher_version, error);

            return Utils.ToBase64String(cipher);
        }

        public static string EncryptWithPasswordAsString(string data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION, Action<Enum> error = null)
        {
            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, error);

            byte[] cipher = Native.Encrypt(Utils.StringToByteArray(data), key, (uint)cipher_version, error);

            return Utils.ToBase64String(cipher);
        }
        

        public static byte[] EncryptWithPassword(byte[] data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION, Action<Enum> error = null)
        {
            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, error);

            byte[] cipher = Native.Encrypt(data, key, (uint)cipher_version, error);

            return cipher;
        }

        // Encrypt base64 string data
        public static byte[] EncryptBase64WithPassword(string b64data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION, Action<Enum> error = null)
        {
            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, error);

            byte[] cipher = Native.Encrypt(Utils.Base64StringToByteArray(b64data), key, (uint)cipher_version, error);

            return cipher;
        }

        public static byte[] EncryptWithPassword(string data, string password, uint iterations = 10000, CipherVersion cipher_version = CIPHER_VERSION, Action<Enum> error = null)
        {
            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, error);

            byte[] cipher = Native.Encrypt(Utils.StringToByteArray(data), key, (uint)cipher_version, error);

            return cipher;
        }


        /***************************************************************
         * 
         *                       Decrypt
         * 
         * **************************************************************/
        
        public static string DecryptWithKeyAsString(string data, byte[] key, uint iterations = 10000, Action<Enum> error = null)
        {
            byte[] result = Native.Decrypt(Utils.Base64StringToByteArray(data), key, error);

            return Utils.ByteArrayToString(result);
        }

        public static byte[] DecryptWithKey(string data, byte[] key, uint iterations = 10000, Action<Enum> error = null)
        {
            byte[] result = Native.Decrypt(Utils.Base64StringToByteArray(data), key, error);

            return result;
        }

        public static string DecryptWithKeyAsString(byte[] data, byte[] key, uint iterations = 10000, Action<Enum> error = null)
        {
            byte[] result = Native.Decrypt(data, key, error);

            return Utils.ByteArrayToString(result);
        }

        public static byte[] DecryptWithKey(byte[] data, byte[] key, uint iterations = 10000, Action<Enum> error = null)
        {
            byte[] result = Native.Decrypt(data, key, error);

            return result;
        }

        public static string DecryptWithPasswordAsString(byte[] data, string password, uint iterations = 10000, Action<Enum> error = null)
        {
            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, error);

            if(key == null)
            {
                return null;
            }

            byte[] result = Native.Decrypt(data, key, error);

            return Utils.ByteArrayToString(result);
        }

        // Encrypt base64 string data and return base64 string
        public static string DecryptWithPasswordAsString(string data, string password, uint iterations = 10000,  Action<Enum> error = null)
        {
            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, error);

            if(key == null)
            {
                return null;
            }

            byte[] result = Native.Decrypt(Utils.Base64StringToByteArray(data), key, error);

            return Utils.ByteArrayToString(result);
        }


        public static byte[] DecryptWithPassword(byte[] data, string password, uint iterations = 10000, Action<Enum> error = null)
        {
            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, error);

            if(key == null)
            {
                return null;
            }

            byte[] result = Native.Decrypt(data, key, error);

            return result;
        }

        // Encrypt base64 string data and return base64 string
        public static byte[] DecryptWithPassword(string data, string password, uint iterations = 10000, Action<Enum> error = null)
        {
            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations, error);

            if(key == null)
            {
                return null;
            }

            byte[] result = Native.Decrypt(Utils.Base64StringToByteArray(data), key, error);

            return result;
        }

        public static Guid GenerateAPIKey(Action<Enum> error = null)
        {
            byte[] apiKey = Native.GenerateKey(16, error);

            if (apiKey == null)
            {
                return Guid.Empty;
            }

            return new Guid(apiKey);
        }
        
        public static void Test()
        {
            Guid api = GenerateAPIKey();
            
            byte[] data = Encoding.UTF8.GetBytes("secretdata");

            byte[] encrypt_result = EncryptWithPassword(data, "secretpass");

            byte[] decrypt_result = DecryptWithPassword(encrypt_result, "secretpass");

            if (Convert.ToBase64String(data) == Convert.ToBase64String(decrypt_result))
            {
                Console.WriteLine("success");
            }
            else
            {
                throw new Exception();
            }

            string string_encrypt_result = EncryptWithPasswordAsString(data, "secretpass");
            string string_decrypt_result = DecryptWithPasswordAsString(string_encrypt_result, "secretpass");

            if (string_decrypt_result == "secretdata")
            {
                Console.WriteLine("success");
            }
            else
            {
                throw new Exception();
            }


            string base64data = Convert.ToBase64String(Encoding.UTF8.GetBytes("secretdata"));

            string_encrypt_result = EncryptBase64WithPasswordAsString(base64data, "secretpass");
            string_decrypt_result = DecryptWithPasswordAsString(string_encrypt_result, "secretpass");

            if (string_decrypt_result == "secretdata")
            {
                Console.WriteLine("success");
            }
            else
            {
                throw new Exception();
            }


            string_encrypt_result = EncryptWithPasswordAsString("secretdata", "secretpass");
            string_decrypt_result = DecryptWithPasswordAsString(string_encrypt_result, "secretpass");

            if (string_decrypt_result == "secretdata")
            {
                Console.WriteLine("success");
            }
            else
            {
                throw new Exception();
            }
        }
    }   
}