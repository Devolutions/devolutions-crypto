namespace Devolutions.Cryptography
{
    public enum DataType 
    {
        Key = 1,
        Cipher = 2,
        Hash = 3
    }

    public enum CipherVersion
    {
        Latest = 0,

        // Aes256CbcHmacSha256
        V1 = 1,

        // XChaCha20Poly1305
        V2 = 2,

        // XChaCha20Poly1305 with DeriveKey length fix
        V2_5 = 2,
    }
}
