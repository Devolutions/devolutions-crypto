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
        Aes256CbcHmacSha256 = 1,
        XChaCha20Poly1305 = 2
    }
}