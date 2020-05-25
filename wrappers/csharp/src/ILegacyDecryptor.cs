namespace Devolutions.Cryptography
{
    public interface ILegacyDecryptor
    {
        byte[] Decrypt(byte[] data, byte[] key);
    }
}
