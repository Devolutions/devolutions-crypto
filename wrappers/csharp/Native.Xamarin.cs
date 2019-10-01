#if ANDROID || IOS || MAC
namespace Devolutions.Cryptography
{
    using System;
    using System.Runtime.InteropServices;

    public static partial class Native
    {
#if IOS
        private const string LibName = "__Internal";
#else
        private const string LibName = "DevolutionsCrypto";
#endif
        [DllImport(LibName, EntryPoint = "Decode", CallingConvention = CallingConvention.Cdecl)]
        public static extern long DecodeNative(byte[] input, UIntPtr input_length, byte[] output, UIntPtr output_length);

        [DllImport(LibName, EntryPoint = "Decrypt", CallingConvention = CallingConvention.Cdecl)]
        private static extern long DecryptNative(byte[] data, UIntPtr dataLength, byte[] key, UIntPtr keyLength, byte[] result, UIntPtr resultLength);

        [DllImport(LibName, EntryPoint = "DeriveKey", CallingConvention = CallingConvention.Cdecl)]
        private static extern long DeriveKeyNative(byte[] key, UIntPtr keyLength, byte[] salt, UIntPtr saltLength, UIntPtr iterations, byte[] result, UIntPtr resultLength);

        [DllImport(LibName, EntryPoint = "Encode", CallingConvention = CallingConvention.Cdecl)]
        public static extern long EncodeNative(byte[] input, UIntPtr input_length, byte[] output, UIntPtr output_length);

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
    }
}
#endif