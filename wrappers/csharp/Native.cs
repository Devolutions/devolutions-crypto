namespace Devolutions.Cryptography
{
    using System;
    using System.Runtime.InteropServices;    
    using System.Reflection;
  
#if RDM
    using System.IO;
#endif

    public static partial class Native
    {

#if RDM
        private const string LibName64 = "DevolutionsCrypto";
        private const string LibName86 = "DevolutionsCrypto";
#endif

#if !ANDROID && !IOS && !MAC && !RDM
        private const string LibName64 = "DevolutionsCrypto-x64";
        private const string LibName86 = "DevolutionsCrypto-x86";
#endif

        static Native()
        {
#if RDM
            // RDM Specific
            // Load the right native DLL depending on the arch
           Assembly assembly = Assembly.GetEntryAssembly();

           if(assembly == null)
           {
               assembly = Assembly.GetExecutingAssembly();
           }

           if(assembly == null)
           {
               throw new System.ComponentModel.Win32Exception();
           }

           string path = Path.GetDirectoryName(assembly.Location);

           path = Path.Combine(path, Environment.Is64BitProcess ? "x64" : "x86");

           bool ok = SetDllDirectory(path);

           if (!ok)
           {
               throw new System.ComponentModel.Win32Exception();
           }
#endif

            Assembly assembly = Assembly.GetExecutingAssembly();

            string managedVersion = assembly.GetName().Version.ToString();
            string nativeVersion = Utils.Version() + ".0";

            if(managedVersion != nativeVersion)
            {
                throw new Exception("Non-matching versions - Managed: " + managedVersion + " Native: " + nativeVersion);
            }
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
                    return null;
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

        public static byte[] DerivePassword(string password, string salt, uint iterations = 10000, Action<Enum> error = null)
        {
            return DeriveKey(Utils.StringToByteArray(password), Utils.StringToByteArray(salt), iterations, error);
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

        public static byte[] Encrypt(byte[] data, byte[] key, uint version = 0, Action<Enum> error = null)
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
                    return null;
                }

                long resultLength = EncryptSizeNative((UIntPtr)data.Length, (UInt16) version);

                byte[] result = new byte[resultLength];

                long res = EncryptNative(data, (UIntPtr)data.Length, key, (UIntPtr)key.Length, result, (UIntPtr)result.Length, (UInt16)version);

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

            if (Convert.ToBase64String(sharedAlice) == Convert.ToBase64String(sharedBob))
            {
                Console.WriteLine("Success");
            }
            else
            {
                throw new Exception();
            }

            byte[] generateKey = GenerateKey(32);

            byte[] dericeKeyResult = DeriveKey(generateKey, null);

            if (dericeKeyResult == null)
            {
                throw new Exception();
            }
        }

#if !ANDROID && !IOS && !MAC
        private static long DecryptNative(byte[] data, UIntPtr dataLength, byte[] key, UIntPtr keyLength, byte[] result, UIntPtr resultLength)
        {
            if(Environment.Is64BitProcess)
            {
                return DecryptNative64(data, dataLength, key, keyLength, result, resultLength);
            }

            return DecryptNative86(data, dataLength, key, keyLength, result, resultLength);
        }

        [DllImport(LibName64, EntryPoint = "Decrypt", CallingConvention = CallingConvention.Cdecl)]
        private static extern long DecryptNative64(byte[] data, UIntPtr dataLength, byte[] key, UIntPtr keyLength, byte[] result, UIntPtr resultLength);

        [DllImport(LibName86, EntryPoint = "Decrypt", CallingConvention = CallingConvention.Cdecl)]
        private static extern long DecryptNative86(byte[] data, UIntPtr dataLength, byte[] key, UIntPtr keyLength, byte[] result, UIntPtr resultLength);

        private static long DeriveKeyNative(byte[] key, UIntPtr keyLength, byte[] salt, UIntPtr saltLength, UIntPtr iterations, byte[] result, UIntPtr resultLength)
        {
            if(Environment.Is64BitProcess)
            {
                return DeriveKeyNative64(key, keyLength, salt, saltLength, iterations, result, resultLength);
            }

            return DeriveKeyNative86(key, keyLength, salt, saltLength, iterations, result, resultLength);

        }

        [DllImport(LibName86, EntryPoint = "DeriveKey", CallingConvention = CallingConvention.Cdecl)]
        private static extern long DeriveKeyNative86(byte[] key, UIntPtr keyLength, byte[] salt, UIntPtr saltLength, UIntPtr iterations, byte[] result, UIntPtr resultLength);

        [DllImport(LibName64, EntryPoint = "DeriveKey", CallingConvention = CallingConvention.Cdecl)]
        private static extern long DeriveKeyNative64(byte[] key, UIntPtr keyLength, byte[] salt, UIntPtr saltLength, UIntPtr iterations, byte[] result, UIntPtr resultLength);

        private static long EncryptNative(byte[] data, UIntPtr dataLength, byte[] key, UIntPtr keyLength, byte[] result, UIntPtr resultLength, UInt16 version)
        {
            if(Environment.Is64BitProcess)
            {
                return EncryptNative64(data, dataLength, key, keyLength, result, resultLength, version);
            }

            return EncryptNative86(data, dataLength, key, keyLength, result, resultLength, version);
        }

        [DllImport(LibName86, EntryPoint = "Encrypt", CallingConvention = CallingConvention.Cdecl)]
        private static extern long EncryptNative86(byte[] data, UIntPtr dataLength, byte[] key, UIntPtr keyLength, byte[] result, UIntPtr resultLength, UInt16 version);


        [DllImport(LibName64, EntryPoint = "Encrypt", CallingConvention = CallingConvention.Cdecl)]
        private static extern long EncryptNative64(byte[] data, UIntPtr dataLength, byte[] key, UIntPtr keyLength, byte[] result, UIntPtr resultLength, UInt16 version);

        private static long EncryptSizeNative(UIntPtr dataLength, UInt16 version)
        {
            if(Environment.Is64BitProcess)
            {
                return EncryptSizeNative64(dataLength, version);
            }

            return EncryptSizeNative86(dataLength, version);
        }

        [DllImport(LibName86, EntryPoint = "EncryptSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long EncryptSizeNative86(UIntPtr dataLength, UInt16 version);


        [DllImport(LibName64, EntryPoint = "EncryptSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long EncryptSizeNative64(UIntPtr dataLength, UInt16 version);

        private static long GenerateKeyExchangeNative(byte[] privateKey, UIntPtr privateKeySize, byte[] publicKey, UIntPtr publicKeySize)
        {
            if(Environment.Is64BitProcess)
            {
                return GenerateKeyExchangeNative64(privateKey,privateKeySize, publicKey, publicKeySize);
            }

            return GenerateKeyExchangeNative86(privateKey,privateKeySize, publicKey, publicKeySize);
        }

        [DllImport(LibName86, EntryPoint = "GenerateKeyExchange", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateKeyExchangeNative86(byte[] privateKey, UIntPtr privateKeySize, byte[] publicKey, UIntPtr publicKeySize);

        [DllImport(LibName64, EntryPoint = "GenerateKeyExchange", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateKeyExchangeNative64(byte[] privateKey, UIntPtr privateKeySize, byte[] publicKey, UIntPtr publicKeySize);

        private static long GenerateKeyExchangeSizeNative()
        {
            if(Environment.Is64BitProcess)
            {
                return GenerateKeyExchangeSizeNative64();
            }

            return GenerateKeyExchangeSizeNative86();
        }

        [DllImport(LibName86, EntryPoint = "GenerateKeyExchangeSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateKeyExchangeSizeNative86();


        [DllImport(LibName64, EntryPoint = "GenerateKeyExchangeSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateKeyExchangeSizeNative64();

        private static long GenerateKeyNative(byte[] key, UIntPtr keyLength)
        {
            if(Environment.Is64BitProcess)
            {
                return GenerateKeyNative64(key, keyLength);
            }

            return GenerateKeyNative86(key, keyLength);
        }

        [DllImport(LibName86, EntryPoint = "GenerateKey", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateKeyNative86(byte[] key, UIntPtr keyLength);

        [DllImport(LibName64, EntryPoint = "GenerateKey", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateKeyNative64(byte[] key, UIntPtr keyLength);

        private static long HashPasswordLengthNative()
        {            
            if(Environment.Is64BitProcess)
            {
                return HashPasswordLengthNative64();
            }

            return HashPasswordLengthNative86();
        }

        [DllImport(LibName86, EntryPoint = "HashPasswordLength", CallingConvention = CallingConvention.Cdecl)]
        private static extern long HashPasswordLengthNative86();

        [DllImport(LibName64, EntryPoint = "HashPasswordLength", CallingConvention = CallingConvention.Cdecl)]
        private static extern long HashPasswordLengthNative64();

        private static long HashPasswordNative(byte[] password, UIntPtr passwordLength, uint iterations, byte[] result, UIntPtr resultLength)
        {
            if(Environment.Is64BitProcess)
            {
                return HashPasswordNative64(password, passwordLength, iterations, result, resultLength);
            }

            return HashPasswordNative86(password, passwordLength, iterations, result, resultLength);
        }

        [DllImport(LibName86, EntryPoint = "HashPassword", CallingConvention = CallingConvention.Cdecl)]
        private static extern long HashPasswordNative86(byte[] password, UIntPtr passwordLength, uint iterations, byte[] result, UIntPtr resultLength);

        [DllImport(LibName64, EntryPoint = "HashPassword", CallingConvention = CallingConvention.Cdecl)]
        private static extern long HashPasswordNative64(byte[] password, UIntPtr passwordLength, uint iterations, byte[] result, UIntPtr resultLength);

        private static uint KeySizeNative()
        {
            if(Environment.Is64BitProcess)
            {
                return KeySizeNative64();
            }

            return KeySizeNative86();
        }
    
        [DllImport(LibName86, EntryPoint = "KeySize", CallingConvention = CallingConvention.Cdecl)]
        private static extern uint KeySizeNative86();

        [DllImport(LibName64, EntryPoint = "KeySize", CallingConvention = CallingConvention.Cdecl)]
        private static extern uint KeySizeNative64();

        private static long MixKeyExchangeNative(byte[] privateKey, UIntPtr privateKeySize, byte[] publicKey, UIntPtr publicKeySize, byte[] shared, UIntPtr sharedSize)
        {
            if(Environment.Is64BitProcess)
            {
                return MixKeyExchangeNative64(privateKey, privateKeySize, publicKey, publicKeySize, shared, sharedSize);
            }

            return MixKeyExchangeNative86(privateKey, privateKeySize, publicKey, publicKeySize, shared, sharedSize);
        }

        [DllImport(LibName86, EntryPoint = "MixKeyExchange", CallingConvention = CallingConvention.Cdecl)]
        private static extern long MixKeyExchangeNative86(byte[] privateKey, UIntPtr privateKeySize, byte[] publicKey, UIntPtr publicKeySize, byte[] shared, UIntPtr sharedSize);

        [DllImport(LibName64, EntryPoint = "MixKeyExchange", CallingConvention = CallingConvention.Cdecl)]
        private static extern long MixKeyExchangeNative64(byte[] privateKey, UIntPtr privateKeySize, byte[] publicKey, UIntPtr publicKeySize, byte[] shared, UIntPtr sharedSize);

        private static long MixKeyExchangeSizeNative()
        {
            if(Environment.Is64BitProcess)
            {
                return MixKeyExchangeSizeNative64();
            }

            return MixKeyExchangeSizeNative86();
        }

        [DllImport(LibName86, EntryPoint = "MixKeyExchangeSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long MixKeyExchangeSizeNative86();

        [DllImport(LibName64, EntryPoint = "MixKeyExchangeSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long MixKeyExchangeSizeNative64();

        private static long VerifyPasswordNative(byte[] password, UIntPtr passwordLength, byte[] hash, UIntPtr hashLength)
        {
            if(Environment.Is64BitProcess)
            {
                return VerifyPasswordNative64(password, passwordLength, hash, hashLength);
            }

            return VerifyPasswordNative86(password, passwordLength, hash, hashLength);
        }

        [DllImport(LibName86, EntryPoint = "VerifyPassword", CallingConvention = CallingConvention.Cdecl)]
        private static extern long VerifyPasswordNative86(byte[] password, UIntPtr passwordLength, byte[] hash, UIntPtr hashLength);

        [DllImport(LibName64, EntryPoint = "VerifyPassword", CallingConvention = CallingConvention.Cdecl)]
        private static extern long VerifyPasswordNative64(byte[] password, UIntPtr passwordLength, byte[] hash, UIntPtr hashLength);

        public static long DecodeNative(string input, UIntPtr input_length, byte[] output, UIntPtr output_length)
        {
            if(Environment.Is64BitProcess)
            {
                return Decode64(input, input_length, output, output_length);
            }

            return Decode86(input, input_length, output, output_length);
        }

        [DllImport(LibName86, EntryPoint = "Decode", CallingConvention = CallingConvention.Cdecl)]
        public static extern long Decode86(string input, UIntPtr input_length, byte[] output, UIntPtr output_length);

        [DllImport(LibName64, EntryPoint = "Decode", CallingConvention = CallingConvention.Cdecl)]
        public static extern long Decode64(string input, UIntPtr input_length, byte[] output, UIntPtr output_length);

        public static long EncodeNative(byte[] input, UIntPtr input_length, byte[] output, UIntPtr output_length)
        {
            if(Environment.Is64BitProcess)
            {
                return Encode64(input, input_length, output, output_length);
            }

            return Encode86(input, input_length, output, output_length);
        }

        [DllImport(LibName86, EntryPoint = "Encode", CallingConvention = CallingConvention.Cdecl)]
        public static extern long Encode86(byte[] input, UIntPtr input_length, byte[] output, UIntPtr output_length);

        [DllImport(LibName64, EntryPoint = "Encode", CallingConvention = CallingConvention.Cdecl)]
        public static extern long Encode64(byte[] input, UIntPtr input_length, byte[] output, UIntPtr output_length);

        public static long VersionNative(byte[] output, UIntPtr output_length)
        {
            if(Environment.Is64BitProcess)
            {
                return Version64(output, output_length);
            }

            return Version86(output, output_length);
        }

        [DllImport(LibName86, EntryPoint = "Version", CallingConvention = CallingConvention.Cdecl)]
        public static extern long Version86(byte[] output, UIntPtr output_length);

        [DllImport(LibName64, EntryPoint = "Version", CallingConvention = CallingConvention.Cdecl)]
        public static extern long Version64(byte[] output, UIntPtr output_length);

        public static long VersionSizeNative()
        {
            if(Environment.Is64BitProcess)
            {
                return VersionSize64();
            }

            return VersionSize86();
        }

        [DllImport(LibName86, EntryPoint = "VersionSize", CallingConvention = CallingConvention.Cdecl)]
        public static extern long VersionSize86();

        [DllImport(LibName64, EntryPoint = "VersionSize", CallingConvention = CallingConvention.Cdecl)]
        public static extern long VersionSize64();
#endif

#if RDM
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool SetDllDirectory(string path);
#endif
    }
}