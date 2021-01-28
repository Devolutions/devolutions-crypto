namespace Devolutions.Cryptography
{
    public interface ILegacyHasher
    {
        bool VerifyPassword(byte[] password, byte[] hash);
    }
}
