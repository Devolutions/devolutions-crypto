namespace Devolutions
{
    using System;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Linq;
    using System.IO;
    using System.Reflection;


    public static class Cryptography
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
            byte[] key = CryptographyNative.DeriveKey(StringToByteArray(password), null, iterations);

            byte[] cipher = CryptographyNative.Encrypt(data, key);

            return ToBase64String(cipher);
        }

        // Encrypt base64 string data and return base64 string
        public static string EncryptBase64WithPasswordAsString(string b64data, string password, uint iterations = 10000)
        {
            byte[] key = CryptographyNative.DeriveKey(StringToByteArray(password), null, iterations);

            byte[] cipher = CryptographyNative.Encrypt(Base64StringToByteArray(b64data), key);

            return ToBase64String(cipher);
        }

        public static string EncryptWithPasswordAsString(string data, string password, uint iterations = 10000)
        {
            byte[] key = CryptographyNative.DeriveKey(StringToByteArray(password), null, iterations);

            byte[] cipher = CryptographyNative.Encrypt(StringToByteArray(data), key);

            return ToBase64String(cipher);
        }
        

        public static byte[] EncryptWithPassword(byte[] data, string password, uint iterations = 10000)
        {
            byte[] key = CryptographyNative.DeriveKey(StringToByteArray(password), null, iterations);

            byte[] cipher = CryptographyNative.Encrypt(data, key);

            return cipher;
        }

        // Encrypt base64 string data
        public static byte[] EncryptBase64WithPassword(string b64data, string password, uint iterations = 10000)
        {
            byte[] key = CryptographyNative.DeriveKey(StringToByteArray(password), null, iterations);

            byte[] cipher = CryptographyNative.Encrypt(Base64StringToByteArray(b64data), key);

            return cipher;
        }

        public static byte[] EncryptWithPassword(string data, string password, uint iterations = 10000)
        {
            byte[] key = CryptographyNative.DeriveKey(StringToByteArray(password), null, iterations);

            byte[] cipher = CryptographyNative.Encrypt(StringToByteArray(data), key);

            return cipher;
        }


        /***************************************************************
         * 
         *                       Decrypt
         * 
         * **************************************************************/

        public static string DecryptWithPasswordAsString(byte[] data, string password, uint iterations = 10000)
        {
            byte[] key = CryptographyNative.DeriveKey(StringToByteArray(password), null, iterations);

            byte[] result = CryptographyNative.Decrypt(data, key);

            return ByteArrayToString(result);
        }

        // Encrypt base64 string data and return base64 string
        public static string DecryptWithPasswordAsString(string data, string password, uint iterations = 10000)
        {
            byte[] key = CryptographyNative.DeriveKey(StringToByteArray(password), null, iterations);

            byte[] result = CryptographyNative.Decrypt(Base64StringToByteArray(data), key);

            return ByteArrayToString(result);
        }


        public static byte[] DecryptWithPassword(byte[] data, string password, uint iterations = 10000)
        {
            byte[] key = CryptographyNative.DeriveKey(StringToByteArray(password), null, iterations);

            byte[] result = CryptographyNative.Decrypt(data, key);

            return result;
        }

        // Encrypt base64 string data and return base64 string
        public static byte[] DecryptWithPassword(string data, string password, uint iterations = 10000)
        {
            byte[] key = CryptographyNative.DeriveKey(StringToByteArray(password), null, iterations);

            byte[] result = CryptographyNative.Decrypt(Base64StringToByteArray(data), key);

            return result;
        }
    }   
}