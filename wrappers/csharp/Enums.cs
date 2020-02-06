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

    public enum DeriveKeyVersion
    {
        Latest = 0,

        // PBKDF2-HMAC-SHA256
        V1 = 1,

        // PBKDF2-HMAC-SHA256 with length fix
        V1_5 = 1,
    }
}