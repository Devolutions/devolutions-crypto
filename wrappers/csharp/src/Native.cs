namespace Devolutions.Cryptography
{
    using System;
#if RDM
    using System.IO;
#endif
    using System.Runtime.InteropServices;
#if !DEBUG
    using System.Reflection;
#endif

    /// <summary>
    /// Contains the bindings to the native rust library.
    /// </summary>
    public static partial class Native
    {
#if RDM
        [DllImport("Kernel32", SetLastError = true)]
        public static extern IntPtr LoadLibrary(string path);

        private const string LibName64 = "DevolutionsCrypto";
        private const string LibName86 = "DevolutionsCrypto";
#endif

#if !ANDROID && !IOS && !MAC_MODERN && !RDM && !DOTNET_CORE
        private const string LibName64 = "DevolutionsCrypto-x64";

        private const string LibName86 = "DevolutionsCrypto-x86";
#endif

#if !DEBUG
        private const string NativeVersion = "||NATIVE_VERSION||";
        private const string ManagedVersion = "||MANAGED_VERSION||";
#endif

        static Native()
        {
#if RDM
            string rid = "win-" + RuntimeInformation.ProcessArchitecture.ToString().ToLower();
            string path = Path.Combine(
                Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), 
                "runtimes", 
                rid, 
                "native",
                $"{ LibName64 }.dll");

            if (LoadLibrary(path) == IntPtr.Zero)
            {
                throw new DevolutionsCryptoException(ManagedError.NativeLibraryLoad, $"LoadLibrary failed for { path }");
            }
#endif

#if !DEBUG
            Assembly assembly = Assembly.GetExecutingAssembly();

            Version assemblyVersion = assembly.GetName().Version;
            Version managedVersion = Version.Parse(ManagedVersion);
            
            if(managedVersion.Revision == -1)
            {
                managedVersion = Version.Parse(ManagedVersion + ".0");
            }

            string nativeVersion = Utils.Version();

            if (managedVersion != assemblyVersion || NativeVersion != nativeVersion)
            {
                throw new DevolutionsCryptoException(ManagedError.IncompatibleVersion, "Non-matching versions - Managed: " + managedVersion + " Native: " + nativeVersion + " Supported : managed(" + ManagedVersion + ") native (" + NativeVersion + ")");
            }
#endif
        }

        [Obsolete("This method has been deprecated. Use Managed.Decrypt instead.")]
        public static byte[] Decrypt(byte[] data, byte[] key)
        {
            return Managed.Decrypt(data, key);
        }

        [Obsolete("This method has been deprecated. Use Managed.DerivePassword instead.")]
        public static byte[] DerivePassword(string password, string salt, uint iterations = 10000)
        {
            return Managed.DerivePassword(password, salt, iterations);
        }

        [Obsolete("This method has been deprecated. Use Managed.DeriveKey instead.")]
        public static byte[] DeriveKey(byte[] key, byte[] salt, uint iterations = 10000, uint length = 32)
        {
            return Managed.DeriveKey(key, salt, iterations, length);
        }

        [Obsolete("This method has been deprecated. Use Managed.Encrypt instead.")]
        public static byte[] Encrypt(byte[] data, byte[] key, uint version = 0)
        {
            return Managed.Encrypt(data, key, (CipherTextVersion)version);
        }

        [Obsolete("This method has been deprecated. Use Managed.GenerateKey instead.")]
        public static byte[] GenerateKey(uint keySize)
        {
            return Managed.GenerateKey(keySize);
        }

        [Obsolete("This method has been deprecated. Use Managed.GenerateKeyPair instead.")]
        public static KeyPair GenerateKeyPair()
        {
            return Managed.GenerateKeyPair();
        }

        [Obsolete("This method has been deprecated. Use Managed.HashPassword instead.")]
        public static byte[] HashPassword(byte[] password, uint iterations = 10000)
        {
            return Managed.HashPassword(password, iterations);
        }

        [Obsolete("This method has been deprecated. Use Managed.HashPassword instead.")]
        public static bool VerifyPassword(byte[] password, byte[] hash)
        {
            return Managed.VerifyPassword(password, hash);
        }

#if !ANDROID && !IOS && !MAC_MODERN && !DOTNET_CORE
        internal static long GenerateSharedKeyNative(UIntPtr nbShares, UIntPtr threshold, UIntPtr size, IntPtr[] shares)
        {
            if (Environment.Is64BitProcess)
            {
                return GenerateSharedKey64(nbShares, threshold, size, shares);
            }

            return GenerateSharedKey86(nbShares, threshold, size, shares);
        }

        internal static long JoinSharesNative(UIntPtr nbShares, UIntPtr sharesLength, IntPtr[] shares, byte[] secret, UIntPtr secretLength)
        {
            if (Environment.Is64BitProcess)
            {
                return JoinShares64(nbShares, sharesLength, shares, secret, secretLength);
            }

            return JoinShares86(nbShares, sharesLength, shares, secret, secretLength);
        }

        internal static long JoinSharesSizeNative(UIntPtr size)
        {
            if (Environment.Is64BitProcess)
            {
                return JoinSharesSize64(size);
            }

            return JoinSharesSize86(size);
        }

        internal static long GenerateSharedKeySizeNative(UIntPtr secretLength)
        {
            if (Environment.Is64BitProcess)
            {
                return GenerateSharedKeySize64(secretLength);
            }

            return GenerateSharedKeySize86(secretLength);
        }

        internal static long DecryptNative(byte[] data, UIntPtr dataLength, byte[] key, UIntPtr keyLength, byte[] result, UIntPtr resultLength)
        {
            if (Environment.Is64BitProcess)
            {
                return DecryptNative64(data, dataLength, key, keyLength, result, resultLength);
            }

            return DecryptNative86(data, dataLength, key, keyLength, result, resultLength);
        }

        internal static long DecryptAsymmetricNative(byte[] data, UIntPtr dataLength, byte[] privateKey, UIntPtr privateKeyLength, byte[] result, UIntPtr resultLength)
        {
            if (Environment.Is64BitProcess)
            {
                return DecryptAsymmetricNative64(data, dataLength, privateKey, privateKeyLength, result, resultLength);
            }

            return DecryptAsymmetricNative86(data, dataLength, privateKey, privateKeyLength, result, resultLength);
        }

        internal static long DeriveKeyArgon2Native(byte[] key, UIntPtr keyLength, byte[] argon2Parameters, UIntPtr argon2ParametersLength, byte[] result, UIntPtr resultLength)
        {
            if (Environment.Is64BitProcess)
            {
                return DeriveKeyArgon2Native64(key, keyLength, argon2Parameters, argon2ParametersLength, result, resultLength);
            }

            return DeriveKeyArgon2Native86(key, keyLength, argon2Parameters, argon2ParametersLength, result, resultLength);
        }

        internal static long DeriveKeyPbkdf2Native(byte[] key, UIntPtr keyLength, byte[] salt, UIntPtr saltLength, System.UInt32 iterations, byte[] result, UIntPtr resultLength)
        {
            if (Environment.Is64BitProcess)
            {
                return DeriveKeyPbkdf2Native64(key, keyLength, salt, saltLength, iterations, result, resultLength);
            }

            return DeriveKeyPbkdf2Native86(key, keyLength, salt, saltLength, iterations, result, resultLength);
        }

        internal static long DeriveKeyPairNative(
            byte[] password,
            UIntPtr passwordLength,
            byte[] parameters,
            UIntPtr parametersLength,
            byte[] privateKey,
            UIntPtr privateKeyLength,
            byte[] publicKey,
            UIntPtr publicKeyLength)
        {
            if (Environment.Is64BitProcess)
            {
                return DeriveKeyPairNative64(password, passwordLength, parameters, parametersLength, privateKey, privateKeyLength, publicKey, publicKeyLength);
            }

            return DeriveKeyPairNative86(password, passwordLength, parameters, parametersLength, privateKey, privateKeyLength, publicKey, publicKeyLength);
        }

        internal static long DeriveKeyPairSizeNative()
        {
            if (Environment.Is64BitProcess)
            {
                return DeriveKeyPairSizeNative64();
            }

            return DeriveKeyPairSizeNative86();
        }

        internal static long GetDefaultArgon2ParametersNative(byte[] argon2Parameters, UIntPtr argon2ParametersLength)
        {
            if (Environment.Is64BitProcess)
            {
                return GetDefaultArgon2ParametersNative64(argon2Parameters, argon2ParametersLength);
            }

            return GetDefaultArgon2ParametersNative86(argon2Parameters, argon2ParametersLength);
        }

        internal static long GetDefaultArgon2ParametersSizeNative()
        {
            if (Environment.Is64BitProcess)
            {
                return GetDefaultArgon2ParametersSizeNative64();
            }

            return GetDefaultArgon2ParametersSizeNative86();
        }

        internal static long EncryptNative(byte[] data, UIntPtr dataLength, byte[] key, UIntPtr keyLength, byte[] result, UIntPtr resultLength, ushort version)
        {
            if (Environment.Is64BitProcess)
            {
                return EncryptNative64(data, dataLength, key, keyLength, result, resultLength, version);
            }

            return EncryptNative86(data, dataLength, key, keyLength, result, resultLength, version);
        }

        internal static long EncryptAsymmetricNative(
            byte[] data,
            UIntPtr dataLength,
            byte[] publicKey,
            UIntPtr publicKeyLength,
            byte[] result,
            UIntPtr resultLength,
            ushort version)
        {
            if (Environment.Is64BitProcess)
            {
                return EncryptAsymmetricNative64(data, dataLength, publicKey, publicKeyLength, result, resultLength, version);
            }

            return EncryptAsymmetricNative86(data, dataLength, publicKey, publicKeyLength, result, resultLength, version);
        }

        internal static long EncryptAsymmetricSizeNative(UIntPtr dataLength, ushort version)
        {
            if (Environment.Is64BitProcess)
            {
                return EncryptAsymmetricSizeNative64(dataLength, version);
            }

            return EncryptAsymmetricSizeNative86(dataLength, version);
        }

        internal static long EncryptSizeNative(UIntPtr dataLength, ushort version)
        {
            if (Environment.Is64BitProcess)
            {
                return EncryptSizeNative64(dataLength, version);
            }

            return EncryptSizeNative86(dataLength, version);
        }

        internal static long GenerateKeyPairNative(byte[] privateKey, UIntPtr privateKeySize, byte[] publicKey, UIntPtr publicKeySize)
        {
            if (Environment.Is64BitProcess)
            {
                return GenerateKeyPairNative64(privateKey, privateKeySize, publicKey, publicKeySize);
            }

            return GenerateKeyPairNative86(privateKey, privateKeySize, publicKey, publicKeySize);
        }

        internal static long GenerateKeyPairSizeNative()
        {
            if (Environment.Is64BitProcess)
            {
                return GenerateKeyPairSizeNative64();
            }

            return GenerateKeyPairSizeNative86();
        }

        internal static long GenerateKeyNative(byte[] key, UIntPtr keyLength)
        {
            if (Environment.Is64BitProcess)
            {
                return GenerateKeyNative64(key, keyLength);
            }

            return GenerateKeyNative86(key, keyLength);
        }

        internal static long HashPasswordLengthNative()
        {
            if (Environment.Is64BitProcess)
            {
                return HashPasswordLengthNative64();
            }

            return HashPasswordLengthNative86();
        }

        internal static long HashPasswordNative(byte[] password, UIntPtr passwordLength, uint iterations, byte[] result, UIntPtr resultLength)
        {
            if (Environment.Is64BitProcess)
            {
                return HashPasswordNative64(password, passwordLength, iterations, result, resultLength);
            }

            return HashPasswordNative86(password, passwordLength, iterations, result, resultLength);
        }

        internal static uint KeySizeNative()
        {
            if (Environment.Is64BitProcess)
            {
                return KeySizeNative64();
            }

            return KeySizeNative86();
        }

        internal static long MixKeyExchangeNative(byte[] privateKey, UIntPtr privateKeySize, byte[] publicKey, UIntPtr publicKeySize, byte[] shared, UIntPtr sharedSize)
        {
            if (Environment.Is64BitProcess)
            {
                return MixKeyExchangeNative64(privateKey, privateKeySize, publicKey, publicKeySize, shared, sharedSize);
            }

            return MixKeyExchangeNative86(privateKey, privateKeySize, publicKey, publicKeySize, shared, sharedSize);
        }

        internal static long MixKeyExchangeSizeNative()
        {
            if (Environment.Is64BitProcess)
            {
                return MixKeyExchangeSizeNative64();
            }

            return MixKeyExchangeSizeNative86();
        }

        internal static long VerifyPasswordNative(byte[] password, UIntPtr passwordLength, byte[] hash, UIntPtr hashLength)
        {
            if (Environment.Is64BitProcess)
            {
                return VerifyPasswordNative64(password, passwordLength, hash, hashLength);
            }

            return VerifyPasswordNative86(password, passwordLength, hash, hashLength);
        }

        internal static long DecodeNative(string input, UIntPtr input_length, byte[] output, UIntPtr output_length)
        {
            if (Environment.Is64BitProcess)
            {
                return Decode64(input, input_length, output, output_length);
            }

            return Decode86(input, input_length, output, output_length);
        }

        internal static long DecodeUrlNative(string input, UIntPtr input_length, byte[] output, UIntPtr output_length)
        {
            if (Environment.Is64BitProcess)
            {
                return DecodeUrl64(input, input_length, output, output_length);
            }

            return DecodeUrl86(input, input_length, output, output_length);
        }

        internal static long EncodeNative(byte[] input, UIntPtr input_length, byte[] output, UIntPtr output_length)
        {
            if (Environment.Is64BitProcess)
            {
                return Encode64(input, input_length, output, output_length);
            }

            return Encode86(input, input_length, output, output_length);
        }

        internal static long EncodeUrlNative(byte[] input, UIntPtr input_length, byte[] output, UIntPtr output_length)
        {
            if (Environment.Is64BitProcess)
            {
                return EncodeUrl64(input, input_length, output, output_length);
            }

            return EncodeUrl86(input, input_length, output, output_length);
        }

        internal static long ValidateHeader(byte[] data, UIntPtr dataLength, ushort dataType)
        {
            if (Environment.Is64BitProcess)
            {
                return ValidateHeader64(data, dataLength, dataType);
            }

            return ValidateHeader86(data, dataLength, dataType);
        }

        internal static long ScryptSimple(byte[] password, UIntPtr passwordLength, byte[] salt, UIntPtr saltLength, byte logN, uint r, uint p, byte[] output, UIntPtr outputLength)
        {
            if (Environment.Is64BitProcess)
            {
                return ScryptSimple64(password, passwordLength, salt, saltLength, logN, r, p, output, outputLength);
            }

            return ScryptSimple86(password, passwordLength, salt, saltLength, logN, r, p, output, outputLength);
        }

        internal static long ScryptSimpleSize()
        {
            if (Environment.Is64BitProcess)
            {
                return ScryptSimpleSize64();
            }

            return ScryptSimpleSize86();
        }

        internal static long Sign(byte[] data, UIntPtr dataLength, byte[] keypair, UIntPtr keypairLength, byte[] result, UIntPtr resultLength, ushort version)
        {
            if (Environment.Is64BitProcess)
            {
                return Sign64(data, dataLength, keypair, keypairLength, result, resultLength, version);
            }

            return Sign86(data, dataLength, keypair, keypairLength, result, resultLength, version);
        }

        internal static long SignSize(ushort version)
        {
            if (Environment.Is64BitProcess)
            {
                return SignSize64(version);
            }

            return SignSize86(version);
        }

        internal static long VerifySignature(byte[] data, UIntPtr dataLength, byte[] publicKey, UIntPtr publicKeyLength, byte[] signature, UIntPtr signatureLength)
        {
            if (Environment.Is64BitProcess)
            {
                return VerifySignature64(data, dataLength, publicKey, publicKeyLength, signature, signatureLength);
            }

            return VerifySignature86(data, dataLength, publicKey, publicKeyLength, signature, signatureLength);
        }

        internal static long VersionNative(byte[] output, UIntPtr outputLength)
        {
            if (Environment.Is64BitProcess)
            {
                return Version64(output, outputLength);
            }

            return Version86(output, outputLength);
        }

        internal static long GenerateSigningKeyPair(byte[] keypair, UIntPtr keypairLength, ushort version)
        {
            if (Environment.Is64BitProcess)
            {
                return GenerateSigningKeyPair64(keypair, keypairLength, version);
            }

            return GenerateSigningKeyPair86(keypair, keypairLength, version);
        }

        internal static long GenerateSigningKeyPairSize(ushort version)
        {
            if (Environment.Is64BitProcess)
            {
                return GenerateSigningKeyPairSize64(version);
            }

            return GenerateSigningKeyPairSize86(version);
        }

        internal static long GetSigningPublicKey(byte[] keypair, UIntPtr keypairLength, byte[] publicKey, UIntPtr publicKeyLength)
        {
            if (Environment.Is64BitProcess)
            {
                return GetSigningPublicKey64(keypair, keypairLength, publicKey, publicKeyLength);
            }

            return GetSigningPublicKey86(keypair, keypairLength, publicKey, publicKeyLength);
        }

        internal static long GetSigningPublicKeySize(byte[] keypair, UIntPtr keypairLength)
        {
            if (Environment.Is64BitProcess)
            {
                return GetSigningPublicKeySize64(keypair, keypairLength);
            }

            return GetSigningPublicKeySize86(keypair, keypairLength);
        }

        internal static long VersionSizeNative()
        {
            if (Environment.Is64BitProcess)
            {
                return VersionSize64();
            }

            return VersionSize86();
        }

        [DllImport(LibName86, EntryPoint = "GenerateKeyExchangeSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateKeyExchangeSizeNative86();

        [DllImport(LibName64, EntryPoint = "GenerateKeyExchangeSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateKeyExchangeSizeNative64();

        [DllImport(LibName64, EntryPoint = "GenerateSharedKey", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateSharedKey64(UIntPtr nbShares, UIntPtr threshold, UIntPtr size, IntPtr[] shares);

        [DllImport(LibName86, EntryPoint = "GenerateSharedKey", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateSharedKey86(UIntPtr nbShares, UIntPtr threshold, UIntPtr size, IntPtr[] shares);

        [DllImport(LibName64, EntryPoint = "GenerateSharedKeySize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateSharedKeySize64(UIntPtr secretLength);

        [DllImport(LibName86, EntryPoint = "GenerateSharedKeySize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateSharedKeySize86(UIntPtr secretLength);

        [DllImport(LibName64, EntryPoint = "JoinShares", CallingConvention = CallingConvention.Cdecl)]
        private static extern long JoinShares64(UIntPtr nbShares, UIntPtr sharesLength, IntPtr[] shares, byte[] secret, UIntPtr secretLength);

        [DllImport(LibName86, EntryPoint = "JoinShares", CallingConvention = CallingConvention.Cdecl)]
        private static extern long JoinShares86(UIntPtr nbShares, UIntPtr sharesLength, IntPtr[] shares, byte[] secret, UIntPtr secretLength);

        [DllImport(LibName64, EntryPoint = "JoinSharesSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long JoinSharesSize64(UIntPtr size);

        [DllImport(LibName86, EntryPoint = "JoinSharesSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long JoinSharesSize86(UIntPtr size);

#pragma warning disable CA2101 // Specify marshaling for P/Invoke string arguments
        [DllImport(LibName86, EntryPoint = "Decode", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern long Decode86(string input, UIntPtr input_length, byte[] output, UIntPtr output_length);

        [DllImport(LibName64, EntryPoint = "Decode", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern long Decode64(string input, UIntPtr input_length, byte[] output, UIntPtr output_length);

        [DllImport(LibName86, EntryPoint = "DecodeUrl", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern long DecodeUrl86(string input, UIntPtr input_length, byte[] output, UIntPtr output_length);

        [DllImport(LibName64, EntryPoint = "DecodeUrl", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern long DecodeUrl64(string input, UIntPtr input_length, byte[] output, UIntPtr output_length);
#pragma warning restore CA2101 // Specify marshaling for P/Invoke string arguments

        [DllImport(LibName64, EntryPoint = "Decrypt", CallingConvention = CallingConvention.Cdecl)]
        private static extern long DecryptNative64(byte[] data, UIntPtr dataLength, byte[] key, UIntPtr keyLength, byte[] result, UIntPtr resultLength);

        [DllImport(LibName86, EntryPoint = "Decrypt", CallingConvention = CallingConvention.Cdecl)]
        private static extern long DecryptNative86(byte[] data, UIntPtr dataLength, byte[] key, UIntPtr keyLength, byte[] result, UIntPtr resultLength);

        [DllImport(LibName64, EntryPoint = "DecryptAsymmetric", CallingConvention = CallingConvention.Cdecl)]
        private static extern long DecryptAsymmetricNative64(byte[] data, UIntPtr dataLength, byte[] privateKey, UIntPtr privateKeyLength, byte[] result, UIntPtr resultLength);

        [DllImport(LibName86, EntryPoint = "DecryptAsymmetric", CallingConvention = CallingConvention.Cdecl)]
        private static extern long DecryptAsymmetricNative86(byte[] data, UIntPtr dataLength, byte[] privateKey, UIntPtr privateKeyLength, byte[] result, UIntPtr resultLength);

        [DllImport(LibName86, EntryPoint = "DeriveKeyArgon2", CallingConvention = CallingConvention.Cdecl)]
        private static extern long DeriveKeyArgon2Native86(
            byte[] key,
            UIntPtr keyLength,
            byte[] argon2Parameters,
            UIntPtr argon2ParametersLength,
            byte[] result,
            UIntPtr resultLength);

        [DllImport(LibName64, EntryPoint = "DeriveKeyArgon2", CallingConvention = CallingConvention.Cdecl)]
        private static extern long DeriveKeyArgon2Native64(
            byte[] key,
            UIntPtr keyLength,
            byte[] argon2Parameters,
            UIntPtr argon2ParametersLength,
            byte[] result,
            UIntPtr resultLength);

        [DllImport(LibName86, EntryPoint = "DeriveKeyPbkdf2", CallingConvention = CallingConvention.Cdecl)]
        private static extern long DeriveKeyPbkdf2Native86(
            byte[] key,
            UIntPtr keyLength,
            byte[] salt,
            UIntPtr saltLength,
            System.UInt32 iterations,
            byte[] result,
            UIntPtr resultLength);

        [DllImport(LibName64, EntryPoint = "DeriveKeyPbkdf2", CallingConvention = CallingConvention.Cdecl)]
        private static extern long DeriveKeyPbkdf2Native64(
            byte[] key,
            UIntPtr keyLength,
            byte[] salt,
            UIntPtr saltLength,
            System.UInt32 iterations,
            byte[] result,
            UIntPtr resultLength);

        [DllImport(LibName86, EntryPoint = "DeriveKeyPair", CallingConvention = CallingConvention.Cdecl)]
        private static extern long DeriveKeyPairNative86(
            byte[] password,
            UIntPtr passwordLength,
            byte[] parameters,
            UIntPtr parametersLength,
            byte[] privateKey,
            UIntPtr privateKeyLength,
            byte[] publicKey,
            UIntPtr publicKeyLength);

        [DllImport(LibName64, EntryPoint = "DeriveKeyPair", CallingConvention = CallingConvention.Cdecl)]
        private static extern long DeriveKeyPairNative64(
            byte[] password,
            UIntPtr passwordLength,
            byte[] parameters,
            UIntPtr parametersLength,
            byte[] privateKey,
            UIntPtr privateKeyLength,
            byte[] publicKey,
            UIntPtr publicKeyLength);

        [DllImport(LibName86, EntryPoint = "DeriveKeyPairSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long DeriveKeyPairSizeNative86();

        [DllImport(LibName64, EntryPoint = "DeriveKeyPairSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long DeriveKeyPairSizeNative64();

        [DllImport(LibName86, EntryPoint = "Encode", CallingConvention = CallingConvention.Cdecl)]
        private static extern long Encode86(byte[] input, UIntPtr input_length, byte[] output, UIntPtr output_length);

        [DllImport(LibName64, EntryPoint = "Encode", CallingConvention = CallingConvention.Cdecl)]
        private static extern long Encode64(byte[] input, UIntPtr input_length, byte[] output, UIntPtr output_length);

        [DllImport(LibName86, EntryPoint = "EncodeUrl", CallingConvention = CallingConvention.Cdecl)]
        private static extern long EncodeUrl86(byte[] input, UIntPtr input_length, byte[] output, UIntPtr output_length);

        [DllImport(LibName64, EntryPoint = "EncodeUrl", CallingConvention = CallingConvention.Cdecl)]
        private static extern long EncodeUrl64(byte[] input, UIntPtr input_length, byte[] output, UIntPtr output_length);

        [DllImport(LibName86, EntryPoint = "Encrypt", CallingConvention = CallingConvention.Cdecl)]
        private static extern long EncryptNative86(byte[] data, UIntPtr dataLength, byte[] key, UIntPtr keyLength, byte[] result, UIntPtr resultLength, ushort version);

        [DllImport(LibName64, EntryPoint = "Encrypt", CallingConvention = CallingConvention.Cdecl)]
        private static extern long EncryptNative64(byte[] data, UIntPtr dataLength, byte[] key, UIntPtr keyLength, byte[] result, UIntPtr resultLength, ushort version);

        [DllImport(LibName86, EntryPoint = "EncryptAsymmetric", CallingConvention = CallingConvention.Cdecl)]
        private static extern long EncryptAsymmetricNative86(
            byte[] data,
            UIntPtr dataLength,
            byte[] publicKey,
            UIntPtr publicKeyLength,
            byte[] result,
            UIntPtr resultLength,
            ushort version);

        [DllImport(LibName64, EntryPoint = "EncryptAsymmetric", CallingConvention = CallingConvention.Cdecl)]
        private static extern long EncryptAsymmetricNative64(
            byte[] data,
            UIntPtr dataLength,
            byte[] publicKey,
            UIntPtr publicKeyLength,
            byte[] result,
            UIntPtr resultLength,
            ushort version);

        [DllImport(LibName86, EntryPoint = "EncryptAsymmetricSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long EncryptAsymmetricSizeNative86(UIntPtr dataLength, ushort version);

        [DllImport(LibName64, EntryPoint = "EncryptAsymmetricSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long EncryptAsymmetricSizeNative64(UIntPtr dataLength, ushort version);

        [DllImport(LibName86, EntryPoint = "EncryptSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long EncryptSizeNative86(UIntPtr dataLength, ushort version);

        [DllImport(LibName64, EntryPoint = "EncryptSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long EncryptSizeNative64(UIntPtr dataLength, ushort version);

        [DllImport(LibName86, EntryPoint = "GetDefaultArgon2Parameters", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GetDefaultArgon2ParametersNative86(byte[] argon2Parameters, UIntPtr argon2ParametersLength);

        [DllImport(LibName64, EntryPoint = "GetDefaultArgon2Parameters", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GetDefaultArgon2ParametersNative64(byte[] argon2Parameters, UIntPtr argon2ParametersLength);

        [DllImport(LibName86, EntryPoint = "GetDefaultArgon2ParametersSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GetDefaultArgon2ParametersSizeNative86();

        [DllImport(LibName64, EntryPoint = "GetDefaultArgon2ParametersSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GetDefaultArgon2ParametersSizeNative64();

        [DllImport(LibName86, EntryPoint = "GenerateKey", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateKeyNative86(byte[] key, UIntPtr keyLength);

        [DllImport(LibName64, EntryPoint = "GenerateKey", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateKeyNative64(byte[] key, UIntPtr keyLength);

        [DllImport(LibName86, EntryPoint = "GenerateKeyPair", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateKeyPairNative86(byte[] privateKey, UIntPtr privateKeySize, byte[] publicKey, UIntPtr publicKeySize);

        [DllImport(LibName64, EntryPoint = "GenerateKeyPair", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateKeyPairNative64(byte[] privateKey, UIntPtr privateKeySize, byte[] publicKey, UIntPtr publicKeySize);

        [DllImport(LibName86, EntryPoint = "GenerateKeyPairSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateKeyPairSizeNative86();

        [DllImport(LibName64, EntryPoint = "GenerateKeyPairSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateKeyPairSizeNative64();

        [DllImport(LibName86, EntryPoint = "HashPassword", CallingConvention = CallingConvention.Cdecl)]
        private static extern long HashPasswordNative86(byte[] password, UIntPtr passwordLength, uint iterations, byte[] result, UIntPtr resultLength);

        [DllImport(LibName64, EntryPoint = "HashPassword", CallingConvention = CallingConvention.Cdecl)]
        private static extern long HashPasswordNative64(byte[] password, UIntPtr passwordLength, uint iterations, byte[] result, UIntPtr resultLength);

        [DllImport(LibName86, EntryPoint = "HashPasswordLength", CallingConvention = CallingConvention.Cdecl)]
        private static extern long HashPasswordLengthNative86();

        [DllImport(LibName64, EntryPoint = "HashPasswordLength", CallingConvention = CallingConvention.Cdecl)]
        private static extern long HashPasswordLengthNative64();

        [DllImport(LibName86, EntryPoint = "KeySize", CallingConvention = CallingConvention.Cdecl)]
        private static extern uint KeySizeNative86();

        [DllImport(LibName64, EntryPoint = "KeySize", CallingConvention = CallingConvention.Cdecl)]
        private static extern uint KeySizeNative64();

        [DllImport(LibName86, EntryPoint = "MixKeyExchange", CallingConvention = CallingConvention.Cdecl)]
        private static extern long MixKeyExchangeNative86(byte[] privateKey, UIntPtr privateKeySize, byte[] publicKey, UIntPtr publicKeySize, byte[] shared, UIntPtr sharedSize);

        [DllImport(LibName64, EntryPoint = "MixKeyExchange", CallingConvention = CallingConvention.Cdecl)]
        private static extern long MixKeyExchangeNative64(byte[] privateKey, UIntPtr privateKeySize, byte[] publicKey, UIntPtr publicKeySize, byte[] shared, UIntPtr sharedSize);

        [DllImport(LibName86, EntryPoint = "MixKeyExchangeSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long MixKeyExchangeSizeNative86();

        [DllImport(LibName64, EntryPoint = "MixKeyExchangeSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long MixKeyExchangeSizeNative64();

        [DllImport(LibName86, EntryPoint = "ValidateHeader", CallingConvention = CallingConvention.Cdecl)]
        private static extern long ValidateHeader86(byte[] data, UIntPtr dataLength, ushort dataType);

        [DllImport(LibName64, EntryPoint = "ValidateHeader", CallingConvention = CallingConvention.Cdecl)]
        private static extern long ValidateHeader64(byte[] data, UIntPtr dataLength, ushort dataType);

        [DllImport(LibName86, EntryPoint = "ScryptSimple", CallingConvention = CallingConvention.Cdecl)]
        private static extern long ScryptSimple86(
            byte[] password,
            UIntPtr passwordLength,
            byte[] salt,
            UIntPtr saltLength,
            byte logN,
            uint r,
            uint p,
            byte[] output,
            UIntPtr outputLength);

        [DllImport(LibName64, EntryPoint = "ScryptSimple", CallingConvention = CallingConvention.Cdecl)]
        private static extern long ScryptSimple64(
            byte[] password,
            UIntPtr passwordLength,
            byte[] salt,
            UIntPtr saltLength,
            byte logN,
            uint r,
            uint p,
            byte[] output,
            UIntPtr outputLength);

        [DllImport(LibName86, EntryPoint = "ScryptSimpleSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long ScryptSimpleSize86();

        [DllImport(LibName64, EntryPoint = "ScryptSimpleSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long ScryptSimpleSize64();

        [DllImport(LibName64, EntryPoint = "Sign", CallingConvention = CallingConvention.Cdecl)]
        private static extern long Sign64(byte[] data, UIntPtr dataLength, byte[] keypair, UIntPtr keypairLength, byte[] result, UIntPtr resultLength, ushort version);

        [DllImport(LibName86, EntryPoint = "Sign", CallingConvention = CallingConvention.Cdecl)]
        private static extern long Sign86(byte[] data, UIntPtr dataLength, byte[] keypair, UIntPtr keypairLength, byte[] result, UIntPtr resultLength, ushort version);

        [DllImport(LibName64, EntryPoint = "SignSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long SignSize64(ushort version);

        [DllImport(LibName86, EntryPoint = "SignSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long SignSize86(ushort version);

        [DllImport(LibName64, EntryPoint = "VerifySignature", CallingConvention = CallingConvention.Cdecl)]
        private static extern long VerifySignature64(byte[] data, UIntPtr dataLength, byte[] publicKey, UIntPtr publicKeyLength, byte[] signature, UIntPtr signatureLength);

        [DllImport(LibName86, EntryPoint = "VerifySignature", CallingConvention = CallingConvention.Cdecl)]
        private static extern long VerifySignature86(byte[] data, UIntPtr dataLength, byte[] publicKey, UIntPtr publicKeyLength, byte[] signature, UIntPtr signatureLength);

        [DllImport(LibName64, EntryPoint = "GenerateSigningKeyPair", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateSigningKeyPair64(byte[] keypair, UIntPtr keypairLength, ushort version);

        [DllImport(LibName86, EntryPoint = "GenerateSigningKeyPair", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateSigningKeyPair86(byte[] keypair, UIntPtr keypairLength, ushort version);

        [DllImport(LibName64, EntryPoint = "GenerateSigningKeyPairSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateSigningKeyPairSize64(ushort version);

        [DllImport(LibName86, EntryPoint = "GenerateSigningKeyPairSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GenerateSigningKeyPairSize86(ushort version);

        [DllImport(LibName64, EntryPoint = "GetSigningPublicKey", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GetSigningPublicKey64(byte[] keypair, UIntPtr keypairLength, byte[] publicKey, UIntPtr publicKeyLength);

        [DllImport(LibName86, EntryPoint = "GetSigningPublicKey", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GetSigningPublicKey86(byte[] keypair, UIntPtr keypairLength, byte[] publicKey, UIntPtr publicKeyLength);

        [DllImport(LibName64, EntryPoint = "GetSigningPublicKeySize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GetSigningPublicKeySize64(byte[] keypair, UIntPtr keypairLength);

        [DllImport(LibName86, EntryPoint = "GetSigningPublicKeySize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long GetSigningPublicKeySize86(byte[] keypair, UIntPtr keypairLength);

        [DllImport(LibName86, EntryPoint = "Version", CallingConvention = CallingConvention.Cdecl)]
        private static extern long Version86(byte[] output, UIntPtr outputLength);

        [DllImport(LibName64, EntryPoint = "Version", CallingConvention = CallingConvention.Cdecl)]
        private static extern long Version64(byte[] output, UIntPtr outputLength);

        [DllImport(LibName86, EntryPoint = "VersionSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long VersionSize86();

        [DllImport(LibName64, EntryPoint = "VersionSize", CallingConvention = CallingConvention.Cdecl)]
        private static extern long VersionSize64();

        [DllImport(LibName86, EntryPoint = "VerifyPassword", CallingConvention = CallingConvention.Cdecl)]
        private static extern long VerifyPasswordNative86(byte[] password, UIntPtr passwordLength, byte[] hash, UIntPtr hashLength);

        [DllImport(LibName64, EntryPoint = "VerifyPassword", CallingConvention = CallingConvention.Cdecl)]
        private static extern long VerifyPasswordNative64(byte[] password, UIntPtr passwordLength, byte[] hash, UIntPtr hashLength);
#endif
    }
}