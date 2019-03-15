namespace Devolutions.Cryptography
{
    using System;
    using System.Linq;
    using System.Text;

    public static class Managed
    {
        private static byte[] StringToByteArray(string data)
        {
            if (data == null)
            {
                return null;
            }

            return Encoding.UTF8.GetBytes(data);
        }

        private static string ToBase64String(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
            {
                return null;
            }

            return Convert.ToBase64String(bytes);
        }

        private static byte[] Base64StringToByteArray(string data)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

            try
            {
                return Convert.FromBase64String(data);
            }
            catch
            {
                return null;
            }
        }

        private static string ByteArrayToString(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                return null;
            }

            return Encoding.UTF8.GetString(data);
        }




        /***************************************************************
         * 
         *                       Encrypt
         * 
         * **************************************************************/
        public static string EncryptWithPasswordAsString(byte[] data, string password, uint iterations = 10000)
        {
            byte[] key = Native.DeriveKey(StringToByteArray(password), null, iterations);

            byte[] cipher = Native.Encrypt(data, key);

            return ToBase64String(cipher);
        }

        // Encrypt base64 string data and return base64 string
        public static string EncryptBase64WithPasswordAsString(string b64data, string password, uint iterations = 10000)
        {
            byte[] key = Native.DeriveKey(StringToByteArray(password), null, iterations);

            byte[] cipher = Native.Encrypt(Base64StringToByteArray(b64data), key);

            return ToBase64String(cipher);
        }

        public static string EncryptWithPasswordAsString(string data, string password, uint iterations = 10000)
        {
            byte[] key = Native.DeriveKey(StringToByteArray(password), null, iterations);

            byte[] cipher = Native.Encrypt(StringToByteArray(data), key);

            return ToBase64String(cipher);
        }
        

        public static byte[] EncryptWithPassword(byte[] data, string password, uint iterations = 10000)
        {
            byte[] key = Native.DeriveKey(StringToByteArray(password), null, iterations);

            byte[] cipher = Native.Encrypt(data, key);

            return cipher;
        }

        // Encrypt base64 string data
        public static byte[] EncryptBase64WithPassword(string b64data, string password, uint iterations = 10000)
        {
            byte[] key = Native.DeriveKey(StringToByteArray(password), null, iterations);

            byte[] cipher = Native.Encrypt(Base64StringToByteArray(b64data), key);

            return cipher;
        }

        public static byte[] EncryptWithPassword(string data, string password, uint iterations = 10000)
        {
            byte[] key = Native.DeriveKey(StringToByteArray(password), null, iterations);

            byte[] cipher = Native.Encrypt(StringToByteArray(data), key);

            return cipher;
        }


        /***************************************************************
         * 
         *                       Decrypt
         * 
         * **************************************************************/

        public static string DecryptWithPasswordAsString(byte[] data, string password, uint iterations = 10000)
        {
            byte[] key = Native.DeriveKey(StringToByteArray(password), null, iterations);

            byte[] result = Native.Decrypt(data, key);

            return ByteArrayToString(result);
        }

        // Encrypt base64 string data and return base64 string
        public static string DecryptWithPasswordAsString(string data, string password, uint iterations = 10000)
        {
            byte[] key = Native.DeriveKey(StringToByteArray(password), null, iterations);

            byte[] result = Native.Decrypt(Base64StringToByteArray(data), key);

            return ByteArrayToString(result);
        }


        public static byte[] DecryptWithPassword(byte[] data, string password, uint iterations = 10000)
        {
            byte[] key = Native.DeriveKey(StringToByteArray(password), null, iterations);

            byte[] result = Native.Decrypt(data, key);

            return result;
        }

        // Encrypt base64 string data and return base64 string
        public static byte[] DecryptWithPassword(string data, string password, uint iterations = 10000)
        {
            byte[] key = Native.DeriveKey(StringToByteArray(password), null, iterations);

            byte[] result = Native.Decrypt(Base64StringToByteArray(data), key);

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

            if (data.SequenceEqual(decrypt_result))
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