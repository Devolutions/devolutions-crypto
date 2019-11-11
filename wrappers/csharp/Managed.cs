namespace Devolutions.Cryptography
{
    using System;
    using System.Text;

    public static class Managed
    {
        public static byte[] DeriveKey(byte[] password, byte[] salt = null, uint iterations = 10000)
        {
            return Native.DeriveKey(password, salt, iterations);
        }

        public static byte[] DeriveKey(string password, byte[] salt = null, uint iterations = 10000)
        {
            return Native.DeriveKey(Utils.StringToByteArray(password), salt, iterations);
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

        public static string EncryptWithKeyAsString(string data, byte[] key, uint version = 0)
        {
            byte[] cipher = Native.Encrypt(Utils.StringToByteArray(data), key, version);

            return Utils.ToBase64String(cipher);
        }

        public static byte[] EncryptWithKey(string data, byte[] key, uint version = 0)
        {
            byte[] cipher = Native.Encrypt(Utils.StringToByteArray(data), key, version);

            return cipher;
        }

        public static string EncryptWithKeyAsString(byte[] data, byte[] key, uint version = 0)
        {
            byte[] cipher = Native.Encrypt(data, key, version);

            return Utils.ToBase64String(cipher);
        }

        public static byte[] EncryptWithKey(byte[] data, byte[] key, uint version = 0)
        {
            byte[] cipher = Native.Encrypt(data, key, version);

            return cipher;
        }

        public static string EncryptWithPasswordAsString(byte[] data, string password, uint iterations = 10000, uint cipher_version = 0)
        {
            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations);

            byte[] cipher = Native.Encrypt(data, key, cipher_version);

            return Utils.ToBase64String(cipher);
        }

        // Encrypt base64 string data and return base64 string
        public static string EncryptBase64WithPasswordAsString(string b64data, string password, uint iterations = 10000, uint cipher_version = 0)
        {
            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations);

            byte[] cipher = Native.Encrypt(Utils.Base64StringToByteArray(b64data), key, cipher_version);

            return Utils.ToBase64String(cipher);
        }

        public static string EncryptWithPasswordAsString(string data, string password, uint iterations = 10000, uint cipher_version = 0)
        {
            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations);

            byte[] cipher = Native.Encrypt(Utils.StringToByteArray(data), key, cipher_version);

            return Utils.ToBase64String(cipher);
        }
        

        public static byte[] EncryptWithPassword(byte[] data, string password, uint iterations = 10000, uint cipher_version = 0)
        {
            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations);

            byte[] cipher = Native.Encrypt(data, key, cipher_version);

            return cipher;
        }

        // Encrypt base64 string data
        public static byte[] EncryptBase64WithPassword(string b64data, string password, uint iterations = 10000, uint cipher_version = 0)
        {
            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations);

            byte[] cipher = Native.Encrypt(Utils.Base64StringToByteArray(b64data), key, cipher_version);

            return cipher;
        }

        public static byte[] EncryptWithPassword(string data, string password, uint iterations = 10000, uint cipher_version = 0)
        {
            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations);

            byte[] cipher = Native.Encrypt(Utils.StringToByteArray(data), key, cipher_version);

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
            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations);

            byte[] result = Native.Decrypt(data, key);

            return Utils.ByteArrayToString(result);
        }

        // Encrypt base64 string data and return base64 string
        public static string DecryptWithPasswordAsString(string data, string password, uint iterations = 10000)
        {
            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations);

            byte[] result = Native.Decrypt(Utils.Base64StringToByteArray(data), key);

            return Utils.ByteArrayToString(result);
        }


        public static byte[] DecryptWithPassword(byte[] data, string password, uint iterations = 10000)
        {
            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations);

            byte[] result = Native.Decrypt(data, key);

            return result;
        }

        // Encrypt base64 string data and return base64 string
        public static byte[] DecryptWithPassword(string data, string password, uint iterations = 10000)
        {
            byte[] key = Native.DeriveKey(Utils.StringToByteArray(password), null, iterations);

            byte[] result = Native.Decrypt(Utils.Base64StringToByteArray(data), key);

            return result;
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