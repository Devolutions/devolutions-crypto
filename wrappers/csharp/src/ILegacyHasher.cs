namespace Devolutions.Cryptography
{
    /// <summary>
    /// Interface for legacy hashers.
    /// </summary>
    public interface ILegacyHasher
    {
        /// <summary>
        /// The method to verify passwords for legacy hashers.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="hash">The hash to validate against.</param>
        /// <returns>The validation result.</returns>
        bool VerifyPassword(byte[] password, byte[] hash);
    }
}
