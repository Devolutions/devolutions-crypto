namespace Devolutions.Cryptography
{
    /// <summary>
    /// The interface for legacy decryptors.
    /// </summary>
    public interface ILegacyDecryptor
    {
        /// <summary>
        /// Decrypt function for legacy decryptors.
        /// </summary>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="key">The key to use for decryption.</param>
        /// <returns>Returns the decryption result.</returns>
        byte[] Decrypt(byte[] data, byte[] key);
    }
}
