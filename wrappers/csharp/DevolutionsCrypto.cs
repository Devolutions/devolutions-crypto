namespace Devolutions
{
    using System;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Linq;

    public class KeyExchange
    {
        public byte[] PrivateKey { get; set; }

        public string PrivateKeyString
        {
            get
            {
                if (this.PrivateKey == null)
                {
                    return null;
                }

                return Convert.ToBase64String(this.PrivateKey);
            }
        }

        public byte[] PublicKey { get; set; }

        public string PublicKeyString
        {
            get
            {
                if (this.PublicKey == null)
                {
                    return null;
                }

                return Convert.ToBase64String(this.PublicKey);
            }
        }
    }

    public static class Cryptography
    {
        public static string Decrypt(string data, string key)
        {
            if (key == null)
            {
                key = string.Empty;
            }

            return ByteArrayToString(Decrypt(Base64StringToByteArray(data), StringToByteArray(key)));
        }

        public static byte[] Decrypt(byte[] data, byte[] key)
        {
            try
            {
                if (data == null || data.Length == 0)
                {
                    return null;
                }

                if (key == null)
                {
                    key = new byte[0];
                }

                byte[] result = new byte[data.Length];

                long res = DecryptNative(data, (UIntPtr)data.Length, key, (UIntPtr)key.Length, result, (UIntPtr)result.Length);

                if (res < 0)
                {
                    return null;
                }

                // If success it returns the real result size, so we resize. 
                Array.Resize(ref result, (int)res);

                return result;
            }
            catch
            {
                return null;
            }
        }

        public static byte[] DeriveKey(byte[] key, byte[] salt, uint iterations = 10000)
        {
            try
            {
                if (key == null || salt == null)
                {
                    return null;
                }

                uint keySize = KeySizeNative();

                byte[] result = new byte[keySize];

                long res = DeriveKeyNative(key, (UIntPtr)key.Length, salt, (UIntPtr)salt.Length, (UIntPtr)iterations, result, (UIntPtr)result.Length);

                if (res < 0)
                {
                    return null;
                }

                return result;
            }
            catch
            {
                return null;
            }
        }

        public static string DeriveKey(string key, string salt, uint iterations = 10000)
        {
            return ByteArrayToString(DeriveKey(StringToByteArray(key), StringToByteArray(salt), iterations));
        }

        public static string Encrypt(string data, string key)
        {
            if (key == null)
            {
                key = string.Empty;
            }

            return ToBase64String(Encrypt(StringToByteArray(data), StringToByteArray(key)));
        }

        public static byte[] Encrypt(byte[] data, byte[] key)
        {
            try
            {
                if (data == null || data.Length == 0)
                {
                    return null;
                }

                if (key == null)
                {
                    key = new byte[0];
                }

                long resultLength = EncryptSizeNative((UIntPtr)data.Length);

                byte[] result = new byte[resultLength];

                long res = EncryptNative(data, (UIntPtr)data.Length, key, (UIntPtr)key.Length, result, (UIntPtr)result.Length);

                if (res < 0)
                {
                    return null;
                }

                return result;
            }
            catch
            {
                return null;
            }
        }

        public static byte[] GenerateKey()
        {
            try
            {
                uint keySize = KeySizeNative();

                byte[] key = new byte[keySize];

                long res = GenerateKeyNative(key, (UIntPtr)keySize);

                if (res < 0)
                {
                    return null;
                }

                return key;
            }
            catch
            {
                return null;
            }
        }

        public static KeyExchange GenerateKeyExchange()
        {
            try
            {
                long keySize = GenerateKeyExchangeSizeNative();

                byte[] publicKey = new byte[keySize];
                byte[] privateKey = new byte[keySize];

                long result = GenerateKeyExchangeNative(publicKey, (UIntPtr)publicKey.Length, privateKey, (UIntPtr)privateKey.Length);

                if (result < 0)
                {
                    return null;
                }

                return new KeyExchange() { PublicKey = publicKey, PrivateKey = privateKey };
            }
            catch
            {
                return null;
            }
        }

        public static string HashPassword(string password, uint iterations = 10000)
        {
            return ToBase64String(HashPassword(StringToByteArray(password), iterations));
        }

        public static byte[] HashPassword(byte[] password, uint iterations = 10000)
        {
            try
            {
                if (password == null || password.Length == 0)
                {
                    return null;
                }

                long hashLength = HashPasswordLengthNative();

                byte[] result = new byte[hashLength];

                long res = HashPasswordNative(password, (UIntPtr)password.Length, iterations, result, (UIntPtr)result.Length);

                if (res < 0)
                {
                    return null;
                }

                return result;
            }
            catch
            {
                return null;
            }
        }

        public static string MixKeyExchange(string publicKey, string privateKey)
        {
            return ToBase64String(MixKeyExchange(Base64StringToByteArray(publicKey), Base64StringToByteArray(privateKey)));
        }

        public static byte[] MixKeyExchange(byte[] publicKey, byte[] privatekey)
        {
            try
            {
                if (publicKey == null || privatekey == null)
                {
                    return null;
                }

                long sharedKeySize = MixKeyExchangeSizeNative();

                byte[] shared = new byte[sharedKeySize];

                long result = MixKeyExchangeNative(publicKey, (UIntPtr)publicKey.Length, privatekey, (UIntPtr)privatekey.Length, shared, (UIntPtr)shared.Length);

                if (result < 0)
                {
                    return null;
                }

                return shared;
            }
            catch
            {
                return null;
            }
        }

        public static void Test()
        {
            var bobresult = Encrypt("Johny", "12345678901234561234567890123456");

            var john = Decrypt(bobresult, "12345678901234561234567890123456");

            if (john != "Johny")
            {
                throw new Exception();
            }

            string hashresult = HashPassword("bob", 10000);

            bool hashverify = VerifyPassword("bob", hashresult);

            if (!hashverify)
            {
                throw new Exception();
            }

            byte[] generateKey = GenerateKey();

            string dericeKeyResult = DeriveKey("", "");

            KeyExchange bob = GenerateKeyExchange();
            KeyExchange alice = GenerateKeyExchange();

            byte[] sharedAlice = MixKeyExchange(bob.PublicKey, alice.PrivateKey);
            byte[] sharedBob = MixKeyExchange(alice.PublicKey, bob.PrivateKey);

            if (sharedAlice.SequenceEqual(sharedBob))
            {
                Console.WriteLine("Youhouu");
            }
            else
            {
                throw new Exception();
            }

            string sharedString1 = MixKeyExchange(bob.PublicKeyString, alice.PrivateKeyString);
            string sharedString2 = MixKeyExchange(alice.PublicKeyString, bob.PrivateKeyString);

            if (sharedString1 == sharedString2)
            {
                Console.WriteLine("Youhouu");
            }
            else
            {
                throw new Exception();
            }
        }

        public static bool VerifyPassword(string password, string hash)
        {
            return VerifyPassword(StringToByteArray(password), Base64StringToByteArray(hash));
        }

        public static bool VerifyPassword(byte[] password, byte[] hash)
        {
            try
            {
                if (password == null || hash == null)
                {
                    return false;
                }

                long res = VerifyPasswordNative(password, (UIntPtr)password.Length, hash, (UIntPtr)hash.Length);

                if (res <= 0)
                {
                    return false;
                }

                return true;
            }
            catch
            {
                return false;
            }
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

        [DllImport("DevolutionsCryptoNative.dll", EntryPoint = "Decrypt", CallingConvention = CallingConvention.Cdecl)]
        private static extern long DecryptNative(byte[] data, UIntPtr dataLength, byte[] key, UIntPtr keyLength, byte[] result, UIntPtr resultLength);

        [DllImport("DevolutionsCryptoNative.dll", EntryPoint = "DeriveKey", CallingConvention = CallingConvention.Cdecl)]
        private static extern long DeriveKeyNative(byte[] key, UIntPtr keyLength, byte[] salt, UIntPtr saltLength, UIntPtr iterations, byte[] result, UIntPtr resultLength);

        [DllImport("DevolutionsCryptoNative.dll", EntryPoint = "Encrypt", CallingConvention = CallingConvention.Cdecl)]
        private static extern long EncryptNative(byte[] data, UIntPtr dataLength, byte[] key, UIntPtr keyLength, byte[] result, UIntPtr resultLength);

        [DllImport("DevolutionsCryptoNative.dll", EntryPoint = "EncryptSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long EncryptSizeNative(UIntPtr dataLength);

        [DllImport("DevolutionsCryptoNative.dll", EntryPoint = "GenerateKeyExchange", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateKeyExchangeNative(byte[] publicKey, UIntPtr publicKeySize, byte[] privateKey, UIntPtr privateKeySize);

        [DllImport("DevolutionsCryptoNative.dll", EntryPoint = "GenerateKeyExchangeSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateKeyExchangeSizeNative();

        [DllImport("DevolutionsCryptoNative.dll", EntryPoint = "GenerateKey", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateKeyNative(byte[] key, UIntPtr keyLength);

        [DllImport("DevolutionsCryptoNative.dll", EntryPoint = "HashPasswordLength", CallingConvention = CallingConvention.Cdecl)]
        private static extern long HashPasswordLengthNative();

        [DllImport("DevolutionsCryptoNative.dll", EntryPoint = "HashPassword", CallingConvention = CallingConvention.Cdecl)]
        private static extern long HashPasswordNative(byte[] password, UIntPtr passwordLength, uint iterations, byte[] result, UIntPtr resultLength);

        [DllImport("DevolutionsCryptoNative.dll", EntryPoint = "KeySize", CallingConvention = CallingConvention.Cdecl)]
        private static extern uint KeySizeNative();

        [DllImport("DevolutionsCryptoNative.dll", EntryPoint = "MixKeyExchange", CallingConvention = CallingConvention.Cdecl)]
        private static extern long MixKeyExchangeNative(byte[] publicKey, UIntPtr publicKeySize, byte[] privateKey, UIntPtr privateKeySize, byte[] shared, UIntPtr sharedSize);

        [DllImport("DevolutionsCryptoNative.dll", EntryPoint = "MixKeyExchangeSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long MixKeyExchangeSizeNative();

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

        [DllImport("DevolutionsCryptoNative.dll", EntryPoint = "VerifyPassword", CallingConvention = CallingConvention.Cdecl)]
        private static extern long VerifyPasswordNative(byte[] password, UIntPtr passwordLength, byte[] hash, UIntPtr hashLength);
    }
}