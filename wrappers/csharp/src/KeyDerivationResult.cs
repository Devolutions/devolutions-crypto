namespace Devolutions.Cryptography
{
    /// <summary>
    /// Holds the result of a structured key derivation: the derived <see cref="SecretKey"/>
    /// and the <see cref="DerivationParameters"/> needed to reproduce the same derivation.
    /// </summary>
    public class KeyDerivationResult
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="KeyDerivationResult"/> class.
        /// </summary>
        public KeyDerivationResult(SecretKey secretKey, DerivationParameters parameters)
        {
            this.SecretKey = secretKey;
            this.Parameters = parameters;
        }

        /// <summary>
        /// Gets the derived secret key for symmetric encryption.
        /// </summary>
        public SecretKey SecretKey { get; }

        /// <summary>
        /// Gets the derivation parameters used to produce the key.
        /// Store these alongside the protected data to re-derive the same key later.
        /// </summary>
        public DerivationParameters Parameters { get; }
    }
}
