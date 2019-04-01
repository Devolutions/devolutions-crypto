namespace Devolutions.Cryptography
{
    using System;
    using System.Runtime.InteropServices;
    using System.Linq;
#if WIN
    using System.IO;
    using System.Reflection;
#endif

    internal static class Native
    {
#if IOS
        private const string LibName = "__Internal";
#else
        private const string LibName = "DevolutionsCrypto";
#endif

        static Native()
        {
#if WIN
            // RDM Specific
            // Load the right native DLL depending on the arch
           string path = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);

           path = Path.Combine(path, IntPtr.Size == 8 ? "x64" : "x86");

           bool ok = SetDllDirectory(path);

           if (!ok)
           {
               throw new System.ComponentModel.Win32Exception();
           }
#endif
        }

        public static byte[] Decrypt(byte[] data, byte[] key,  Action<Enum> error = null)
        {
            try
            {
                if (data == null || data.Length == 0)
                {
                    error?.Invoke(ManagedError.InvalidParameter);

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
                    HandleError(res, error);

                    return null;
                }

                // If success it returns the real result size, so we resize. 
                Array.Resize(ref result, (int)res);

                return result;
            }
            catch
            {
                error?.Invoke(ManagedError.Error);

                return null;
            }
        }

        private static void HandleError(long errorCode, Action<Enum> error)
        {
            if (error == null)
            {
                return;
            }

            if (Enum.IsDefined(typeof(NativeError), errorCode))
            {
                error?.Invoke((NativeError)errorCode);
            }
            else
            {
                error?.Invoke(ManagedError.Error);
            }
        }

        public static byte[] DeriveKey(byte[] key, byte[] salt, uint iterations = 10000, Action<Enum> error = null)
        {
            try
            {
                if (key == null)
                {
                    error?.Invoke(ManagedError.InvalidParameter);

                    return null;
                }

                uint keySize = KeySizeNative();

                byte[] result = new byte[keySize];

                int saltLength = salt == null ? 0 : salt.Length;

                long res = DeriveKeyNative(key, (UIntPtr)key.Length, salt, (UIntPtr)saltLength, (UIntPtr)iterations, result, (UIntPtr)result.Length);

                if (res < 0)
                {
                    HandleError(res, error);

                    return null;
                }

                return result;
            }
            catch
            {
                error?.Invoke(ManagedError.Error);

                return null;
            }
        }

        public static byte[] Encrypt(byte[] data, byte[] key, Action<Enum> error = null)
        {
            try
            {
                if (data == null || data.Length == 0)
                {
                    error?.Invoke(ManagedError.InvalidParameter);

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
                    HandleError(res, error);

                    return null;
                }

                return result;
            }
            catch
            {
                error?.Invoke(ManagedError.Error);

                return null;
            }
        }

        public static byte[] GenerateKey(Action<Enum> error = null)
        {
            try
            {
                uint keySize = KeySizeNative();

                byte[] key = new byte[keySize];

                long res = GenerateKeyNative(key, (UIntPtr)keySize);

                if (res < 0)
                {
                    HandleError(res, error);

                    return null;
                }

                return key;
            }
            catch
            {
                error?.Invoke(ManagedError.Error);

                return null;
            }
        }

        public static byte[] GenerateKey(uint keySize, Action<Enum> error = null)
        {
            try
            {
                byte[] key = new byte[keySize];

                long res = GenerateKeyNative(key, (UIntPtr)keySize);

                if (res < 0)
                {
                    HandleError(res, error);

                    return null;
                }

                return key;
            }
            catch
            {
                error?.Invoke(ManagedError.Error);

                return null;
            }
        }

        public static KeyExchange GenerateKeyExchange(Action<Enum> error = null)
        {
            try
            {
                long keySize = GenerateKeyExchangeSizeNative();

                byte[] publicKey = new byte[keySize];
                byte[] privateKey = new byte[keySize];

                long res = GenerateKeyExchangeNative(privateKey, (UIntPtr)privateKey.Length, publicKey, (UIntPtr)publicKey.Length);

                if (res < 0)
                {
                    HandleError(res, error);

                    return null;
                }

                return new KeyExchange() { PublicKey = publicKey, PrivateKey = privateKey };
            }
            catch
            {
                error?.Invoke(ManagedError.Error);

                return null;
            }
        }

        public static byte[] HashPassword(byte[] password, uint iterations = 10000, Action<Enum> error = null)
        {
            try
            {
                if (password == null || password.Length == 0)
                {
                    error?.Invoke(ManagedError.InvalidParameter);

                    return null;
                }

                long hashLength = HashPasswordLengthNative();

                byte[] result = new byte[hashLength];

                long res = HashPasswordNative(password, (UIntPtr)password.Length, iterations, result, (UIntPtr)result.Length);

                if (res < 0)
                {
                    HandleError(res, error);

                    return null;
                }

                return result;
            }
            catch
            {
                error?.Invoke(ManagedError.Error);

                return null;
            }
        }

        public static byte[] MixKeyExchange(byte[] privatekey, byte[] publicKey, Action<Enum> error = null)
        {
            try
            {
                if (publicKey == null || privatekey == null)
                {
                    error?.Invoke(ManagedError.InvalidParameter);

                    return null;
                }

                long sharedKeySize = MixKeyExchangeSizeNative();

                byte[] shared = new byte[sharedKeySize];

                long res = MixKeyExchangeNative(privatekey, (UIntPtr)privatekey.Length, publicKey, (UIntPtr)publicKey.Length, shared, (UIntPtr)shared.Length);

                if (res < 0)
                {
                    HandleError(res, error);

                    return null;
                }

                return shared;
            }
            catch
            {
                error?.Invoke(ManagedError.Error);

                return null;
            }
        }

        public static bool VerifyPassword(byte[] password, byte[] hash, Action<Enum> error = null)
        {
            try
            {
                if (password == null || hash == null)
                {
                    error?.Invoke(ManagedError.InvalidParameter);

                    return false;
                }

                long res = VerifyPasswordNative(password, (UIntPtr)password.Length, hash, (UIntPtr)hash.Length);

                if (res <= 0)
                {
                    HandleError(res, error);

                    return false;
                }

                return true;
            }
            catch
            {
                error?.Invoke(ManagedError.Error);

                return false;
            }
        }

        public static void Test()
        {
            KeyExchange bob = GenerateKeyExchange();
            KeyExchange alice = GenerateKeyExchange();

            byte[] sharedAlice = MixKeyExchange(alice.PrivateKey, bob.PublicKey);
            byte[] sharedBob = MixKeyExchange(bob.PrivateKey, alice.PublicKey);

            if (sharedAlice.SequenceEqual(sharedBob))
            {
                Console.WriteLine("Success");
            }
            else
            {
                throw new Exception();
            }

            byte[] generateKey = GenerateKey();

            byte[] dericeKeyResult = DeriveKey(generateKey, null);

            if (dericeKeyResult == null)
            {
                throw new Exception();
            }
        }

        [DllImport(LibName, EntryPoint = "Decrypt", CallingConvention = CallingConvention.Cdecl)]
        private static extern long DecryptNative(byte[] data, UIntPtr dataLength, byte[] key, UIntPtr keyLength, byte[] result, UIntPtr resultLength);

        [DllImport(LibName, EntryPoint = "DeriveKey", CallingConvention = CallingConvention.Cdecl)]
        private static extern long DeriveKeyNative(byte[] key, UIntPtr keyLength, byte[] salt, UIntPtr saltLength, UIntPtr iterations, byte[] result, UIntPtr resultLength);

        [DllImport(LibName, EntryPoint = "Encrypt", CallingConvention = CallingConvention.Cdecl)]
        private static extern long EncryptNative(byte[] data, UIntPtr dataLength, byte[] key, UIntPtr keyLength, byte[] result, UIntPtr resultLength);

        [DllImport(LibName, EntryPoint = "EncryptSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long EncryptSizeNative(UIntPtr dataLength);

        [DllImport(LibName, EntryPoint = "GenerateKeyExchange", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateKeyExchangeNative(byte[] privateKey, UIntPtr privateKeySize, byte[] publicKey, UIntPtr publicKeySize);

        [DllImport(LibName, EntryPoint = "GenerateKeyExchangeSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateKeyExchangeSizeNative();

        [DllImport(LibName, EntryPoint = "GenerateKey", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateKeyNative(byte[] key, UIntPtr keyLength);

        [DllImport(LibName, EntryPoint = "HashPasswordLength", CallingConvention = CallingConvention.Cdecl)]
        private static extern long HashPasswordLengthNative();

        [DllImport(LibName, EntryPoint = "HashPassword", CallingConvention = CallingConvention.Cdecl)]
        private static extern long HashPasswordNative(byte[] password, UIntPtr passwordLength, uint iterations, byte[] result, UIntPtr resultLength);

        [DllImport(LibName, EntryPoint = "KeySize", CallingConvention = CallingConvention.Cdecl)]
        private static extern uint KeySizeNative();

        [DllImport(LibName, EntryPoint = "MixKeyExchange", CallingConvention = CallingConvention.Cdecl)]
        private static extern long MixKeyExchangeNative(byte[] privateKey, UIntPtr privateKeySize, byte[] publicKey, UIntPtr publicKeySize, byte[] shared, UIntPtr sharedSize);

        [DllImport(LibName, EntryPoint = "MixKeyExchangeSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long MixKeyExchangeSizeNative();

        [DllImport(LibName, EntryPoint = "VerifyPassword", CallingConvention = CallingConvention.Cdecl)]
        private static extern long VerifyPasswordNative(byte[] password, UIntPtr passwordLength, byte[] hash, UIntPtr hashLength);

#if WIN
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool SetDllDirectory(string path);
#endif
    }
}