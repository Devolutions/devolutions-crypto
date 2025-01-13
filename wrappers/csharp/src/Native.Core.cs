// Xamarin and .NET Core bindings

#if ANDROID || IOS || MACOS || NETCOREAPP || NETSTANDARD
namespace Devolutions.Cryptography
{
    using System;
    using System.Runtime.InteropServices;

    /// <summary>
    /// Contains the bindings to the native rust library.
    /// </summary>
    public static partial class Native
    {
#if IOS
        private const string LibName = "libDevolutionsCrypto.framework/libDevolutionsCrypto";
#else
        private const string LibName = "DevolutionsCrypto";
#endif
        [DllImport(LibName, EntryPoint = "GenerateSharedKeySize", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long GenerateSharedKeySizeNative(UIntPtr secretLength);

        [DllImport(LibName, EntryPoint = "GenerateSharedKey", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long GenerateSharedKeyNative(UIntPtr nbShares, UIntPtr threshold, UIntPtr size, IntPtr[] shares);

        [DllImport(LibName, EntryPoint = "JoinShares", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long JoinSharesNative(UIntPtr nbShares, UIntPtr sharesLength, IntPtr[] shares, byte[] secret, UIntPtr secretLength);

        [DllImport(LibName, EntryPoint = "JoinSharesSize", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long JoinSharesSizeNative(UIntPtr size);

        [DllImport(LibName, EntryPoint = "Decode", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long DecodeNative(string input, UIntPtr input_length, byte[] output, UIntPtr output_length);

        [DllImport(LibName, EntryPoint = "DecodeUrl", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long DecodeUrlNative(string input, UIntPtr input_length, byte[] output, UIntPtr output_length);

        [DllImport(LibName, EntryPoint = "Decrypt", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long DecryptNative(byte[] data, UIntPtr dataLength, byte[] key, UIntPtr keyLength, byte[] aad, UIntPtr aadLength, byte[] result, UIntPtr resultLength);

        [DllImport(LibName, EntryPoint = "DecryptAsymmetric", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long DecryptAsymmetricNative(byte[] data, UIntPtr dataLength, byte[] privateKey, UIntPtr privateKeyLength, byte[] aad, UIntPtr aadLength, byte[] result, UIntPtr resultLength);

        [DllImport(LibName, EntryPoint = "DeriveKeyArgon2", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long DeriveKeyArgon2Native(byte[] key, UIntPtr keyLength, byte[] argon2Parameters, UIntPtr argon2ParametersLength, byte[] result, UIntPtr resultLength);

        [DllImport(LibName, EntryPoint = "DeriveKeyPbkdf2", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long DeriveKeyPbkdf2Native(byte[] key, UIntPtr keyLength, byte[] salt, UIntPtr saltLength, System.UInt32 iterations, byte[] result, UIntPtr resultLength);

        [DllImport(LibName, EntryPoint = "DeriveKeyPair", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long DeriveKeyPairNative(byte[] password, UIntPtr passwordLength, byte[] parameters, UIntPtr parametersLength, byte[] privateKey, UIntPtr privateKeyLength, byte[] publicKey, UIntPtr publicKeyLength);

        [DllImport(LibName, EntryPoint = "DeriveKeyPairSize", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long DeriveKeyPairSizeNative();

        [DllImport(LibName, EntryPoint = "Encode", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long EncodeNative(byte[] input, UIntPtr input_length, byte[] output, UIntPtr output_length);

        [DllImport(LibName, EntryPoint = "EncodeUrl", CallingConvention = CallingConvention.Cdecl)]

        internal static extern long EncodeUrlNative(byte[] input, UIntPtr input_length, byte[] output, UIntPtr output_length);

        [DllImport(LibName, EntryPoint = "Encrypt", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long EncryptNative(byte[] data, UIntPtr dataLength, byte[] key, UIntPtr keyLength, byte[] aad, UIntPtr aadLength, byte[] result, UIntPtr resultLength, UInt16 version);

        [DllImport(LibName, EntryPoint = "EncryptAsymmetric", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long EncryptAsymmetricNative(byte[] data, UIntPtr dataLength, byte[] publicKey, UIntPtr publicKeyLength, byte[] aad, UIntPtr aadLength, byte[] result, UIntPtr resultLength, ushort version);

        [DllImport(LibName, EntryPoint = "EncryptAsymmetricSize", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long EncryptAsymmetricSizeNative(UIntPtr dataLength, ushort version);

        [DllImport(LibName, EntryPoint = "EncryptSize", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long EncryptSizeNative(UIntPtr dataLength, UInt16 version);

        [DllImport(LibName, EntryPoint = "GenerateKeyPair", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long GenerateKeyPairNative(byte[] privateKey, UIntPtr privateKeySize, byte[] publicKey, UIntPtr publicKeySize);

        [DllImport(LibName, EntryPoint = "GenerateKeyPairSize", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long GenerateKeyPairSizeNative();

        [DllImport(LibName, EntryPoint = "GenerateKey", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long GenerateKeyNative(byte[] key, UIntPtr keyLength);

        [DllImport(LibName, EntryPoint = "GetDefaultArgon2Parameters", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long GetDefaultArgon2ParametersNative(byte[] argon2Parameters, UIntPtr argon2ParametersLength);

        [DllImport(LibName, EntryPoint = "GetDefaultArgon2ParametersSize", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long GetDefaultArgon2ParametersSizeNative();

        [DllImport(LibName, EntryPoint = "HashPasswordLength", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long HashPasswordLengthNative();

        [DllImport(LibName, EntryPoint = "HashPassword", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long HashPasswordNative(byte[] password, UIntPtr passwordLength, uint iterations, byte[] result, UIntPtr resultLength);

        [DllImport(LibName, EntryPoint = "KeySize", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint KeySizeNative();

        [DllImport(LibName, EntryPoint = "MixKeyExchange", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long MixKeyExchangeNative(byte[] privateKey, UIntPtr privateKeySize, byte[] publicKey, UIntPtr publicKeySize, byte[] shared, UIntPtr sharedSize);

        [DllImport(LibName, EntryPoint = "MixKeyExchangeSize", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long MixKeyExchangeSizeNative();

        [DllImport(LibName, EntryPoint = "ValidateHeader", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long ValidateHeader(byte[] data, UIntPtr dataLength, ushort dataType);

        [DllImport(LibName, EntryPoint = "VerifyPassword", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long VerifyPasswordNative(byte[] password, UIntPtr passwordLength, byte[] hash, UIntPtr hashLength);

        [DllImport(LibName, EntryPoint = "Version", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long VersionNative(byte[] output, UIntPtr output_length);

        [DllImport(LibName, EntryPoint = "VersionSize", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long VersionSizeNative();

        [DllImport(LibName, EntryPoint = "ScryptSimple", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long ScryptSimple(byte[] password, UIntPtr passwordLength, byte[] salt, UIntPtr saltLength, byte logN,  uint r, uint p, byte[] output, UIntPtr outputLength);

        [DllImport(LibName, EntryPoint = "ScryptSimpleSize", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long ScryptSimpleSize();

        [DllImport(LibName, EntryPoint = "Sign", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long Sign(byte[] data, UIntPtr dataLength, byte[] keypair, UIntPtr keypairLength, byte[] result, UIntPtr resultLength, ushort version);

        [DllImport(LibName, EntryPoint = "SignSize", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long SignSize(ushort version);

        [DllImport(LibName, EntryPoint = "VerifySignature", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long VerifySignature(byte[] data, UIntPtr dataLength, byte[] publicKey, UIntPtr publicKeyLength, byte[] signature, UIntPtr signatureLength);

        [DllImport(LibName, EntryPoint = "GenerateSigningKeyPair", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long GenerateSigningKeyPair(byte[] keypair, UIntPtr keypairLength, ushort version);

        [DllImport(LibName, EntryPoint = "GenerateSigningKeyPairSize", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long GenerateSigningKeyPairSize(ushort version);

        [DllImport(LibName, EntryPoint = "GetSigningPublicKey", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long GetSigningPublicKey(byte[] keypair, UIntPtr keypairLength, byte[] publicKey, UIntPtr publicKeyLength);

        [DllImport(LibName, EntryPoint = "GetSigningPublicKeySize", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long GetSigningPublicKeySize(byte[] keypair, UIntPtr keypairLength);

        [DllImport(LibName, EntryPoint = "ConstantTimeEquals", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long ConstantTimeEquals(byte[] x, UIntPtr xLength, byte[] y, UIntPtr yLength);
    }
}
#endif