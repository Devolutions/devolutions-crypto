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
        V1 = 1,
        V2 = 2
    }
}